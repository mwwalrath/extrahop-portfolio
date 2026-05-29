# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-15

### Added

- Initial release.
- Pulls RevealX 360 audit log via REST API with bounded retry (token refresh on 401, exponential backoff on 5xx and connection errors).
- Extracts source IPs from authentication events. Falls back to regex extraction from the `details` field for UI Login events, where the structured `src_ip` field is empty.
- Classifies events as UI Login, REST API Auth, or post-auth operation, and as success or fail.
- Aggregates source IPs into /24 buckets with success/fail counts per category, distinct user count, and operation list.
- Classifies each /24 as `public`, `private`, `cgnat`, `loopback`, `link_local`, `reserved`, or `invalid` to highlight Allow List candidates.
- CSV injection mitigation on user-controlled cells.
- Hostname validation on the `EH_API_HOST` environment variable.
- Argument validation on `--lookback-days`, `--page-size`, `--max-pages`.
- Warning when the run exits due to `--max-pages` before reaching the lookback cutoff.
- Test suite covering pure functions and retry logic.
