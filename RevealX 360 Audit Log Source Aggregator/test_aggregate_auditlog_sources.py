# Copyright (c) 2026, Matthew Walrath. All rights reserved.
# Licensed under the BSD 2-Clause License. See LICENSE for details.
"""Tests for aggregate_auditlog_sources.

Run:
    pip install pytest
    pytest test_aggregate_auditlog_sources.py -v
"""

from unittest.mock import patch, MagicMock

import pytest
import requests

from aggregate_auditlog_sources import (
    extract_source_ip,
    classify_address,
    classify_event,
    to_bucket,
    sanitize_csv_cell,
    validate_hostname,
    fetch_page_with_retry,
    RETRY_ATTEMPTS,
)


# ---------------------------------------------------------------------------
# extract_source_ip
# ---------------------------------------------------------------------------

class TestExtractSourceIp:
    def test_structured_single_ip(self):
        assert extract_source_ip({"src_ip": "1.2.3.4"}) == "1.2.3.4"

    def test_structured_xff_chain_returns_first(self):
        assert extract_source_ip({"src_ip": "1.2.3.4, 100.127.0.25"}) == "1.2.3.4"

    def test_structured_xff_with_extra_whitespace(self):
        assert extract_source_ip({"src_ip": "  1.2.3.4  ,  100.127.0.25"}) == "1.2.3.4"

    def test_structured_invalid_falls_through_to_details(self):
        body = {"src_ip": "not-an-ip", "details": "Login succeeded from 5.6.7.8"}
        assert extract_source_ip(body) == "5.6.7.8"

    def test_details_regex_fallback(self):
        body = {"details": "Login succeeded from 5.6.7.8 with identity provider 'aws-cognito'"}
        assert extract_source_ip(body) == "5.6.7.8"

    def test_details_login_failed_pattern(self):
        body = {"details": "Login failed from 9.9.9.9 with bad credentials"}
        assert extract_source_ip(body) == "9.9.9.9"

    def test_details_no_from_keyword(self):
        body = {"details": "Generated bundle export 12345"}
        assert extract_source_ip(body) is None

    def test_empty_body(self):
        assert extract_source_ip({}) is None

    def test_none_body(self):
        assert extract_source_ip(None) is None

    def test_non_dict_body(self):
        assert extract_source_ip("not a dict") is None
        assert extract_source_ip(["not", "a", "dict"]) is None

    def test_malformed_ip_in_regex(self):
        body = {"details": "Login succeeded from 999.999.999.999"}
        assert extract_source_ip(body) is None

    def test_empty_src_ip_field(self):
        body = {"src_ip": "", "details": "Login succeeded from 1.1.1.1"}
        assert extract_source_ip(body) == "1.1.1.1"

    def test_src_ip_whitespace_only(self):
        body = {"src_ip": "   ", "details": "Login succeeded from 1.1.1.1"}
        assert extract_source_ip(body) == "1.1.1.1"


# ---------------------------------------------------------------------------
# classify_address
# ---------------------------------------------------------------------------

class TestClassifyAddress:
    @pytest.mark.parametrize("ip,expected", [
        # Public, routable
        ("8.8.8.8", "public"),
        ("1.1.1.1", "public"),
        ("3.125.31.111", "public"),
        # RFC 1918
        ("10.0.0.1", "private"),
        ("10.241.2.55", "private"),
        ("172.16.0.1", "private"),
        ("172.31.255.255", "private"),
        ("192.168.0.1", "private"),
        ("192.168.255.255", "private"),
        # RFC 6598 (CGNAT / AWS NLB internal)
        ("100.64.0.1", "cgnat"),
        ("100.127.0.25", "cgnat"),
        ("100.127.255.255", "cgnat"),
        # Special
        ("127.0.0.1", "loopback"),
        ("127.255.255.255", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "reserved"),  # multicast
        # Garbage
        ("not-an-ip", "invalid"),
        ("", "invalid"),
        ("999.999.999.999", "invalid"),
    ])
    def test_classification(self, ip, expected):
        assert classify_address(ip) == expected

    def test_cgnat_lower_boundary(self):
        # Just below 100.64.0.0
        assert classify_address("100.63.255.255") == "public"

    def test_cgnat_upper_boundary(self):
        # Just above 100.127.255.255
        assert classify_address("100.128.0.0") == "public"


# ---------------------------------------------------------------------------
# classify_event
# ---------------------------------------------------------------------------

class TestClassifyEvent:
    def test_login_success(self):
        assert classify_event("Login", "Login succeeded from 1.2.3.4") == ("UI", "success")

    def test_login_fail(self):
        assert classify_event("Login", "Login failed for user x") == ("UI", "fail")

    def test_auth_success(self):
        assert classify_event("Auth", "ID xxx. Granted privilege") == ("API", "success")

    def test_auth_fail(self):
        assert classify_event("Auth", "Failed: POST /oauth2/token operation") == ("API", "fail")

    def test_other_operation(self):
        assert classify_event("Create REST API Credential", "ID xxx.") == ("other", "success")

    def test_none_operation_and_details(self):
        assert classify_event(None, None) == ("other", "success")

    def test_empty_strings(self):
        assert classify_event("", "") == ("other", "success")

    def test_case_insensitive_operation(self):
        assert classify_event("LOGIN", "Login succeeded from 1.2.3.4") == ("UI", "success")
        assert classify_event("auth", "Failed: POST /oauth2/token") == ("API", "fail")


# ---------------------------------------------------------------------------
# to_bucket
# ---------------------------------------------------------------------------

class TestToBucket:
    def test_ipv4_to_slash_24(self):
        assert to_bucket("10.241.2.55") == "10.241.2.0/24"

    def test_ipv4_at_low_boundary(self):
        assert to_bucket("1.2.3.0") == "1.2.3.0/24"

    def test_ipv4_at_high_boundary(self):
        assert to_bucket("1.2.3.255") == "1.2.3.0/24"

    def test_ipv6_to_slash_48(self):
        assert to_bucket("2001:db8::1") == "2001:db8::/48"

    def test_invalid_returns_none(self):
        assert to_bucket("not-an-ip") is None
        assert to_bucket("") is None
        assert to_bucket("999.999.999.999") is None


# ---------------------------------------------------------------------------
# sanitize_csv_cell
# ---------------------------------------------------------------------------

class TestSanitizeCsvCell:
    @pytest.mark.parametrize("value,expected", [
        # Safe values pass through unchanged
        ("normal value", "normal value"),
        ("user@example.com", "user@example.com"),  # @ in middle is fine
        ("1.2.3.4", "1.2.3.4"),
        ("Login", "Login"),
        ("", ""),
        # Empty / None
        (None, ""),
        # Formula triggers get prefixed
        ("=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"),
        ("+1234567890", "'+1234567890"),
        ("-2+3", "'-2+3"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tfoo", "'\tfoo"),
        ("\rbar", "'\rbar"),
        # Edge: single trigger character alone
        ("=", "'="),
        ("+", "'+"),
    ])
    def test_sanitization(self, value, expected):
        assert sanitize_csv_cell(value) == expected

    def test_coerces_non_string(self):
        # Numbers and other types get stringified
        assert sanitize_csv_cell(42) == "42"
        assert sanitize_csv_cell(True) == "True"


# ---------------------------------------------------------------------------
# validate_hostname
# ---------------------------------------------------------------------------

class TestValidateHostname:
    @pytest.mark.parametrize("host", [
        "tenant.api.cloud.extrahop.com",
        "example-tenant.api.cloud.extrahop.com",
        "example.com",
        "a-b.c-d.example",
        "host123",
    ])
    def test_valid_hostnames(self, host):
        assert validate_hostname(host) is True

    @pytest.mark.parametrize("host", [
        "",
        None,
        "https://example.com",          # scheme
        "example.com/path",             # path
        "example.com:443",              # port
        "example.com with spaces",      # whitespace
        "evil.com#@legit.com",          # URL injection attempt
        "example.com\nLocation: evil",  # CRLF injection
        "example.com/oauth2/token",
    ])
    def test_invalid_hostnames(self, host):
        assert validate_hostname(host) is False


# ---------------------------------------------------------------------------
# fetch_page_with_retry
# ---------------------------------------------------------------------------

def _http_error(status):
    """Build a requests.HTTPError carrying a response with the given status code."""
    resp = MagicMock()
    resp.status_code = status
    err = requests.HTTPError(response=resp)
    return err


class TestFetchPageWithRetry:
    def test_success_first_attempt(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch:
            mock_fetch.return_value = [{"id": 1}]
            page, token = fetch_page_with_retry(
                "h", lambda: "new", "old", 10, 0
            )
        assert page == [{"id": 1}]
        assert token == "old"
        assert mock_fetch.call_count == 1

    def test_401_triggers_token_refresh_and_retries(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch:
            mock_fetch.side_effect = [_http_error(401), [{"id": 1}]]
            page, token = fetch_page_with_retry(
                "h", lambda: "new", "old", 10, 0
            )
        assert page == [{"id": 1}]
        assert token == "new"
        assert mock_fetch.call_count == 2

    def test_5xx_triggers_backoff_and_retries(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch, \
             patch("aggregate_auditlog_sources.time.sleep") as mock_sleep:
            mock_fetch.side_effect = [_http_error(503), [{"id": 1}]]
            page, _ = fetch_page_with_retry(
                "h", lambda: "new", "old", 10, 0
            )
        assert page == [{"id": 1}]
        assert mock_sleep.call_count == 1

    def test_4xx_non_401_raises_immediately(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch:
            mock_fetch.side_effect = _http_error(403)
            with pytest.raises(requests.HTTPError):
                fetch_page_with_retry("h", lambda: "new", "old", 10, 0)
        assert mock_fetch.call_count == 1

    def test_max_attempts_exhausted_on_5xx(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch, \
             patch("aggregate_auditlog_sources.time.sleep"):
            mock_fetch.side_effect = _http_error(500)
            with pytest.raises(requests.HTTPError):
                fetch_page_with_retry("h", lambda: "new", "old", 10, 0)
        assert mock_fetch.call_count == RETRY_ATTEMPTS

    def test_connection_error_retries(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch, \
             patch("aggregate_auditlog_sources.time.sleep"):
            mock_fetch.side_effect = [requests.ConnectionError("net"), [{"id": 1}]]
            page, _ = fetch_page_with_retry(
                "h", lambda: "new", "old", 10, 0
            )
        assert page == [{"id": 1}]
        assert mock_fetch.call_count == 2

    def test_timeout_retries(self):
        with patch("aggregate_auditlog_sources.fetch_page") as mock_fetch, \
             patch("aggregate_auditlog_sources.time.sleep"):
            mock_fetch.side_effect = [requests.Timeout("slow"), [{"id": 1}]]
            page, _ = fetch_page_with_retry(
                "h", lambda: "new", "old", 10, 0
            )
        assert page == [{"id": 1}]
        assert mock_fetch.call_count == 2
