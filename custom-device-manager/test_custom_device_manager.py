# Copyright (c) 2026, Matthew Walrath. All rights reserved.
# Licensed under the BSD 2-Clause License. See LICENSE for details.
"""
Unit tests for custom_device_manager pure functions.

Run with: python -m pytest test_custom_device_manager.py -v
"""
import csv

import pytest

from custom_device_manager import (
    _criteria_match,
    _parse_criteria_from_row,
    _parse_csv_to_device_map,
    RunSummary,
)


# ---------------------------------------------------------------------------
# _parse_criteria_from_row
# ---------------------------------------------------------------------------

class TestParseCriteriaFromRow:

    def test_basic_ipaddr(self):
        row = {'ipaddr': '10.0.0.0/24', 'ipaddr_direction': 'any'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result == {'ipaddr': '10.0.0.0/24', 'ipaddr_direction': 'any'}

    def test_empty_row_returns_empty_dict(self):
        row = {'ipaddr': '', 'src_port_min': ''}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result == {}

    def test_missing_keys_returns_empty_dict(self):
        row = {'name': 'Seattle', 'description': 'Office'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result == {}

    def test_integer_fields_are_converted(self):
        row = {'ipaddr': '10.0.0.1', 'dst_port_min': '80', 'dst_port_max': '443'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result['dst_port_min'] == 80
        assert result['dst_port_max'] == 443
        assert isinstance(result['dst_port_min'], int)

    def test_invalid_integer_skipped(self):
        row = {'dst_port_min': 'abc'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert 'dst_port_min' not in result

    def test_port_out_of_range_skipped(self):
        row = {'src_port_min': '0'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert 'src_port_min' not in result

    def test_port_max_boundary(self):
        row = {'src_port_max': '65535'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result['src_port_max'] == 65535

    def test_port_above_max_skipped(self):
        row = {'src_port_max': '65536'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert 'src_port_max' not in result

    def test_vlan_fields(self):
        row = {'vlan_min': '100', 'vlan_max': '200'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result == {'vlan_min': 100, 'vlan_max': 200}

    def test_ipaddr_peer_without_ipaddr_removed(self):
        row = {'ipaddr_peer': '10.0.0.1'}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert 'ipaddr_peer' not in result

    def test_ipaddr_peer_with_direction_any_removed(self):
        row = {
            'ipaddr': '10.0.0.0/24',
            'ipaddr_direction': 'any',
            'ipaddr_peer': '10.0.0.1',
        }
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert 'ipaddr_peer' not in result
        assert result['ipaddr'] == '10.0.0.0/24'

    def test_ipaddr_peer_with_direction_src_kept(self):
        row = {
            'ipaddr': '10.0.0.0/24',
            'ipaddr_direction': 'src',
            'ipaddr_peer': '10.0.0.1',
        }
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result['ipaddr_peer'] == '10.0.0.1'

    def test_whitespace_stripped(self):
        row = {'ipaddr': '  10.0.0.0/24  ', 'ipaddr_direction': ' dst '}
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result['ipaddr'] == '10.0.0.0/24'
        assert result['ipaddr_direction'] == 'dst'

    def test_full_row(self):
        row = {
            'ipaddr': '192.168.1.0/24',
            'ipaddr_direction': 'dst',
            'ipaddr_peer': '10.0.0.1',
            'src_port_min': '1024',
            'src_port_max': '65535',
            'dst_port_min': '443',
            'dst_port_max': '443',
            'vlan_min': '10',
            'vlan_max': '20',
        }
        result = _parse_criteria_from_row(row, 'TestDevice')
        assert result == {
            'ipaddr': '192.168.1.0/24',
            'ipaddr_direction': 'dst',
            'ipaddr_peer': '10.0.0.1',
            'src_port_min': 1024,
            'src_port_max': 65535,
            'dst_port_min': 443,
            'dst_port_max': 443,
            'vlan_min': 10,
            'vlan_max': 20,
        }


# ---------------------------------------------------------------------------
# _criteria_match
# ---------------------------------------------------------------------------

class TestCriteriaMatch:

    def test_exact_match(self):
        existing = {'ipaddr': '10.0.0.0/24', 'dst_port_min': 80}
        target = {'ipaddr': '10.0.0.0/24', 'dst_port_min': 80}
        assert _criteria_match(existing, target) is True

    def test_subset_match(self):
        """Target has fewer fields than existing. Should still match."""
        existing = {'ipaddr': '10.0.0.0/24', 'dst_port_min': 80, 'vlan_min': 10}
        target = {'ipaddr': '10.0.0.0/24'}
        assert _criteria_match(existing, target) is True

    def test_no_match_different_value(self):
        existing = {'ipaddr': '10.0.0.0/24'}
        target = {'ipaddr': '192.168.1.0/24'}
        assert _criteria_match(existing, target) is False

    def test_no_match_missing_key(self):
        """Target has a key that existing doesn't have."""
        existing = {'ipaddr': '10.0.0.0/24'}
        target = {'ipaddr': '10.0.0.0/24', 'dst_port_min': 80}
        assert _criteria_match(existing, target) is False

    def test_empty_target_matches_everything(self):
        existing = {'ipaddr': '10.0.0.0/24', 'dst_port_min': 80}
        assert _criteria_match(existing, {}) is True

    def test_both_empty(self):
        assert _criteria_match({}, {}) is True

    def test_type_sensitive(self):
        """Port as int vs string should not match."""
        existing = {'dst_port_min': 80}
        target = {'dst_port_min': '80'}
        assert _criteria_match(existing, target) is False


# ---------------------------------------------------------------------------
# _parse_csv_to_device_map
# ---------------------------------------------------------------------------

def _write_csv(path, rows):
    """Helper to write a list of dicts to a CSV file."""
    if not rows:
        # Write empty file
        with open(path, 'w', newline='') as f:
            f.write('')
        return
    fieldnames = list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


class TestParseCsvToDeviceMap:

    def test_single_device_single_criteria(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'description': 'Office', 'ipaddr': '10.0.0.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert 'Seattle' in result
        assert result['Seattle']['name'] == 'Seattle'
        assert result['Seattle']['description'] == 'Office'
        assert len(result['Seattle']['criteria']) == 1
        assert result['Seattle']['criteria'][0]['ipaddr'] == '10.0.0.0/24'

    def test_single_device_multiple_criteria(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'description': 'Office', 'ipaddr': '10.0.0.0/24'},
            {'name': 'Seattle', 'description': 'Office', 'ipaddr': '10.0.1.0/24'},
            {'name': 'Seattle', 'description': 'Office', 'ipaddr': '10.0.2.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert len(result) == 1
        assert len(result['Seattle']['criteria']) == 3

    def test_multiple_devices(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'ipaddr': '10.0.0.0/24'},
            {'name': 'Portland', 'ipaddr': '10.0.1.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert len(result) == 2
        assert 'Seattle' in result
        assert 'Portland' in result

    def test_empty_name_skipped(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': '', 'ipaddr': '10.0.0.0/24'},
            {'name': 'Seattle', 'ipaddr': '10.0.1.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert len(result) == 1
        assert 'Seattle' in result

    def test_empty_csv_returns_empty_dict(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        # Write just headers, no rows
        with open(csv_path, 'w', newline='') as f:
            f.write('name,ipaddr\n')
        result = _parse_csv_to_device_map(str(csv_path))
        assert result == {}

    def test_default_author(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'ipaddr': '10.0.0.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert result['Seattle']['author'] == 'API Automation'

    def test_custom_author(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'author': 'Matt', 'ipaddr': '10.0.0.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert result['Seattle']['author'] == 'Matt'

    def test_disabled_flag(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'disabled': 'true', 'ipaddr': '10.0.0.0/24'},
            {'name': 'Portland', 'disabled': 'false', 'ipaddr': '10.0.1.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert result['Seattle']['disabled'] is True
        assert result['Portland']['disabled'] is False

    def test_extrahop_id_included_when_present(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'extrahop_id': 'sea-01', 'ipaddr': '10.0.0.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert result['Seattle']['extrahop_id'] == 'sea-01'

    def test_extrahop_id_omitted_when_empty(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'extrahop_id': '', 'ipaddr': '10.0.0.0/24'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert 'extrahop_id' not in result['Seattle']

    def test_row_with_no_criteria_fields(self, tmp_path):
        csv_path = tmp_path / 'devices.csv'
        _write_csv(csv_path, [
            {'name': 'Seattle', 'description': 'No filters'},
        ])
        result = _parse_csv_to_device_map(str(csv_path))
        assert result['Seattle']['criteria'] == []

    def test_bom_handling(self, tmp_path):
        """CSV saved from Excel with BOM should parse correctly."""
        csv_path = tmp_path / 'bom.csv'
        with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
            f.write('name,ipaddr\n')
            f.write('Seattle,10.0.0.0/24\n')
        result = _parse_csv_to_device_map(str(csv_path))
        assert 'Seattle' in result


# ---------------------------------------------------------------------------
# RunSummary
# ---------------------------------------------------------------------------

class TestRunSummary:

    def test_initial_state(self):
        s = RunSummary()
        assert s.created == 0
        assert s.patched == 0
        assert s.deleted == 0
        assert s.skipped == 0
        assert s.failed == 0
        assert s.audited == 0

    def test_log_no_ops(self, capsys):
        s = RunSummary()
        s.log()
        captured = capsys.readouterr()
        assert 'no operations performed' in captured.out

    def test_log_with_counts(self, capsys):
        s = RunSummary()
        s.created = 3
        s.failed = 1
        s.log()
        captured = capsys.readouterr()
        assert '3 created' in captured.out
        assert '1 failed' in captured.out
