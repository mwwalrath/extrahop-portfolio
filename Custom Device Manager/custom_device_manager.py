#!/usr/bin/env python3
# Copyright (c) 2026, Matthew Walrath. All rights reserved.
# Licensed under the BSD 2-Clause License. See LICENSE for details.
"""
custom_device_manager.py

Bulk audit, create, patch, and delete of ExtraHop custom devices via the
REST API. Reads CSV input for device definitions and appliance
credentials. Supports dry-run preview, three patch modes (replace,
append, remove), and automatic reconnection across multiple appliances.

Version: 1.0
Author:  Matthew Walrath
"""

import argparse
from datetime import datetime
import csv
import http.client
import json
import logging
import os
import ssl
from time import sleep

# Module-level logger. Handlers are attached in setup_logging() so this
# module can be imported as a library without side effects.
logger = logging.getLogger(__name__)
_console_handler = None


def setup_logging(log_level='INFO'):
    """
    Configure file and console logging. Call once from main().

    Returns the console handler so the caller can adjust its level later.
    """
    global _console_handler

    current_datetime = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
    log_folder = 'logs'
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(
        log_folder, f'custom_device_manager_log_{current_datetime}.log'
    )

    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setFormatter(
        logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    )

    _console_handler = logging.StreamHandler()
    _console_handler.setFormatter(
        logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    )

    logger.addHandler(file_handler)
    logger.addHandler(_console_handler)
    logger.setLevel(log_level.upper())
    _console_handler.setLevel(log_level.upper())

    return _console_handler


class ConnectionManager:
    """
    Manages an HTTPS connection to an ExtraHop appliance with automatic
    reconnection on failure. Holds the hostname so it can rebuild the
    connection transparently when a request fails mid-run.
    """

    def __init__(self, hostname, max_retries=3, timeout=10, verify_ssl=True):
        self.hostname = hostname
        self.max_retries = max_retries
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        if verify_ssl:
            self._ssl_context = ssl.create_default_context()
        else:
            self._ssl_context = ssl._create_unverified_context()

        self._connection = None

    def _connect(self):
        """Create a fresh HTTPS connection."""
        logger.debug(f'Opening HTTPS connection to {self.hostname}')
        self._connection = http.client.HTTPSConnection(
            self.hostname, 443, timeout=self.timeout,
            context=self._ssl_context
        )
        return self._connection

    def connect(self):
        """
        Establish the initial connection with retries.

        Returns:
            bool: True if connected, False if all attempts failed.
        """
        logger.info(f'Setting up HTTPS connection to {self.hostname}')
        for attempt in range(self.max_retries):
            try:
                self._connect()
                return True
            except Exception as e:
                logger.error(f'Connection attempt {attempt + 1}/{self.max_retries} '
                             f'to {self.hostname} failed: {e}')
                if attempt < self.max_retries - 1:
                    sleep(2)
        logger.error(f'Failed to connect to {self.hostname} after {self.max_retries} attempts')
        return False

    def send_request(self, method, url, headers, body=None):
        """
        Sends an HTTP request with automatic reconnection on failure.

        Returns the response and body together so callers never accidentally
        read the body twice.

        Returns:
            tuple: (http.client.HTTPResponse, bytes) or (None, None) on failure.
        """
        logger.debug(f'Sending {method} request to {url}')
        for attempt in range(self.max_retries):
            try:
                if self._connection is None:
                    self._connect()
                self._connection.request(method, url, headers=headers, body=body)
                response = self._connection.getresponse()
                response_body = response.read()
                logger.debug(f'Received response: {response.status} {response.reason}')
                return response, response_body
            except Exception as e:
                logger.error(f'Request failed ({method} {url}), attempt '
                             f'{attempt + 1}/{self.max_retries}: {e}')
                # Force a fresh connection on next attempt
                self._connection = None
                if attempt < self.max_retries - 1:
                    sleep(2)
        logger.error(f'Failed {method} {url} after {self.max_retries} attempts')
        return None, None


class RunSummary:
    """Tracks operation counts for a final summary."""

    def __init__(self):
        self.created = 0
        self.patched = 0
        self.deleted = 0
        self.skipped = 0
        self.failed = 0
        self.audited = 0

    def log(self):
        parts = []
        if self.created:
            parts.append(f'{self.created} created')
        if self.patched:
            parts.append(f'{self.patched} patched')
        if self.deleted:
            parts.append(f'{self.deleted} deleted')
        if self.skipped:
            parts.append(f'{self.skipped} skipped')
        if self.failed:
            parts.append(f'{self.failed} failed')
        if self.audited:
            parts.append(f'{self.audited} audited')
        if parts:
            msg = 'Summary: ' + ', '.join(parts)
        else:
            msg = 'Summary: no operations performed'
        logger.info(msg)
        print(f'\n{msg}')


def _decode(body):
    """Safely decode response body bytes to string."""
    if isinstance(body, bytes):
        return body.decode('utf-8', errors='replace')
    return body or ''


def _open_csv(path):
    """Open a CSV file with utf-8-sig to handle Excel BOMs gracefully."""
    return open(path, mode='r', encoding='utf-8-sig', newline='')


# Criteria field names expected by the ExtraHop API.
CRITERIA_KEYS = [
    'ipaddr', 'ipaddr_direction', 'ipaddr_peer',
    'src_port_min', 'src_port_max',
    'dst_port_min', 'dst_port_max',
    'vlan_min', 'vlan_max'
]
INT_KEYS = {'vlan_min', 'vlan_max', 'dst_port_min', 'dst_port_max',
            'src_port_min', 'src_port_max'}
PORT_KEYS = {'src_port_min', 'src_port_max', 'dst_port_min', 'dst_port_max'}


def _parse_criteria_from_row(row, device_name):
    """
    Parse a single CSV row into a criteria dict.

    Returns an empty dict if no criteria fields have values.
    """
    criteria = {}
    for key in CRITERIA_KEYS:
        val = row.get(key, '').strip()
        if val:
            if key in INT_KEYS:
                try:
                    int_val = int(val)
                except ValueError:
                    logger.warning(f'Invalid integer for {key}={val} on device '
                                   f'{device_name}. Skipping field.')
                    continue
                if key in PORT_KEYS and not (1 <= int_val <= 65535):
                    logger.warning(f'Port value out of range for {key}={int_val} '
                                   f'on device {device_name}. Must be 1-65535. '
                                   f'Skipping field.')
                    continue
                criteria[key] = int_val
            else:
                criteria[key] = val

    # Validate ipaddr_peer constraint
    if 'ipaddr_peer' in criteria:
        if 'ipaddr' not in criteria:
            logger.warning(f'ipaddr_peer specified without ipaddr on device '
                           f'{device_name}. Removing ipaddr_peer.')
            del criteria['ipaddr_peer']
        elif criteria.get('ipaddr_direction') == 'any':
            logger.warning(f'ipaddr_peer is not valid when ipaddr_direction '
                           f'is "any" on device {device_name}. Removing '
                           f'ipaddr_peer.')
            del criteria['ipaddr_peer']

    return criteria


def _parse_csv_to_device_map(csv_path):
    """
    Parse a CSV file into a dict of {device_name: device_payload}.

    Each device payload has name, author, description, disabled, and a
    criteria list built by merging all rows with the same name.

    Returns:
        dict: {name: {name, author, description, disabled, criteria: [...], ...}}
    """
    with _open_csv(csv_path) as csv_file:
        rows = list(csv.DictReader(csv_file))

    if not rows:
        logger.warning(f'No devices found in {csv_path}. Nothing to do.')
        return {}

    processed = {}
    for row in rows:
        name = row.get('name', '').strip()
        if not name:
            logger.warning(f'Skipping row with empty name: {row}')
            continue

        if name not in processed:
            device_entry = {
                'name': name,
                'author': row.get('author', 'API Automation').strip() or 'API Automation',
                'description': row.get('description', '').strip(),
                'disabled': row.get('disabled', 'false').strip().lower() == 'true',
                'criteria': []
            }
            extrahop_id = row.get('extrahop_id', '').strip()
            if extrahop_id:
                device_entry['extrahop_id'] = extrahop_id
            processed[name] = device_entry

        criteria = _parse_criteria_from_row(row, name)
        if criteria:
            processed[name]['criteria'].append(criteria)

    return processed


def _criteria_match(existing, target):
    """
    Check if an existing criteria dict matches a target for removal.

    A match means every field present in target has the same value in
    existing. This lets the CSV specify just ipaddr to remove a criteria
    without listing every field.
    """
    for key, val in target.items():
        if existing.get(key) != val:
            return False
    return True


def get_custom_devices(conn, api_key, include_criteria=False):
    """
    Retrieves all custom devices from the appliance.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        include_criteria (bool): Whether to include criteria in the response.

    Returns:
        list: A list of custom device dicts, or an empty list on failure.
    """
    logger.info(f'Retrieving custom devices from {conn.hostname}')
    try:
        ic = str(include_criteria).lower()
        url = f'/api/v1/customdevices?include_criteria={ic}'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}'
        }
        response, body = conn.send_request('GET', url, headers)
        if response and response.status == 200:
            logger.info(f'{response.status}: Custom devices successfully retrieved.')
            return json.loads(body)
        else:
            status = response.status if response else 'No response'
            reason = response.reason if response else 'N/A'
            logger.error(f'{status}: {reason}: {_decode(body)}')
            return []
    except Exception as e:
        logger.error(f'Exception occurred while retrieving custom devices: {e}')
        return []


def search_device(conn, api_key, device_name):
    """
    Searches for a device by name on the ExtraHop appliance.

    Used internally by audit_custom_devices to look up the L2/L3 device
    record that backs a custom device, which is needed to query metrics.

    Returns:
        list: A list of matching device dicts, or an empty list on failure.
    """
    logger.debug(f'Searching for device: {device_name}...')
    try:
        url = '/api/v1/devices/search'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}',
            'Content-Type': 'application/json'
        }
        payload = {
            'filter': {
                'field': 'name',
                'operand': device_name,
                'operator': '='
            }
        }
        response, body = conn.send_request('POST', url, headers, body=json.dumps(payload))
        if response and response.status == 200:
            logger.debug(f'{response.status}: Device successfully retrieved.')
            return json.loads(body)
        else:
            status = response.status if response else 'No response'
            reason = response.reason if response else 'N/A'
            logger.error(f'{status}: {reason}: {_decode(body)}')
            return []
    except Exception as e:
        logger.error(f'Exception occurred while retrieving device: {e}')
        return []


def metric_query(conn, api_key, device_id, metric_window_ms=-1209600000):
    """
    Queries total bytes (net:bytes) for a device over a time window.

    Used internally by audit_custom_devices when --include_metrics is set.
    Returns raw metric data from the ExtraHop /api/v1/metrics endpoint.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        device_id: The device ID to query.
        metric_window_ms (int): Negative millisecond offset from now.
            Default is -1209600000 (14 days).

    Returns:
        dict or None: The metrics data, or None on failure.
    """
    logger.debug(f'Performing metric query on device id: {device_id}')
    try:
        url = '/api/v1/metrics'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}',
            'Content-Type': 'application/json'
        }
        payload = {
            'cycle': 'auto',
            'from': metric_window_ms,
            'until': 0,
            'object_type': 'device',
            'object_ids': [device_id],
            'metric_category': 'net',
            'metric_specs': [{'name': 'bytes'}]
        }
        response, body = conn.send_request('POST', url, headers, body=json.dumps(payload))
        if response and response.status == 200:
            logger.debug(f'{response.status}: Queried metrics successfully retrieved.')
            return json.loads(body)
        else:
            status = response.status if response else 'No response'
            reason = response.reason if response else 'N/A'
            logger.error(f'{status}: {reason}: {_decode(body)}')
            return None
    except Exception as e:
        logger.error(f'Exception occurred while retrieving metrics: {e}')
        return None


def create_custom_device(conn, api_key, payload, dry_run=False):
    """
    Creates a custom device on the ExtraHop platform.

    Returns:
        tuple: (success: bool, response_body: str or None)
    """
    name = payload.get('name', '')
    if dry_run:
        logger.info(f'[DRY RUN] Would create custom device: {name}')
        logger.debug(f'[DRY RUN] Payload: {json.dumps(payload, indent=2)}')
        return True, None

    logger.info(f'Creating custom device: {name}')
    try:
        url = '/api/v1/customdevices'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}',
            'Content-Type': 'application/json'
        }
        response, body = conn.send_request('POST', url, headers, body=json.dumps(payload))
        if not response:
            logger.error(f'No response received while creating custom device: {name}')
            return False, None
        body_str = _decode(body)
        if response.status == 201:
            logger.info(f'{response.status}: Custom device successfully created.')
            return True, None
        else:
            logger.error(f'{response.status}: {response.reason}: {body_str}')
            logger.debug(f'{json.dumps(payload, indent=2, sort_keys=True)}')
            return False, body_str
    except Exception as e:
        logger.error(f'Exception occurred while creating custom device: {e}')
        return False, None


def patch_custom_device(conn, api_key, device_id, payload, dry_run=False):
    """
    Patches (updates) a custom device on the ExtraHop platform.

    Returns:
        bool: True if the patch succeeded, False otherwise.
    """
    name = payload.get('name', '')
    if dry_run:
        logger.info(f'[DRY RUN] Would patch device: {name} (id: {device_id})')
        logger.debug(f'[DRY RUN] Payload: {json.dumps(payload, indent=2)}')
        return True

    logger.info(f'Patching {name} (id: {device_id})...')
    try:
        url = f'/api/v1/customdevices/{device_id}'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}',
            'Content-Type': 'application/json'
        }
        response, body = conn.send_request('PATCH', url, headers, body=json.dumps(payload))
        if not response:
            logger.error(f'No response received while patching custom device: {name}')
            return False
        if response.status == 204:
            logger.info(f'{response.status}: Custom device successfully patched.')
            return True
        else:
            logger.error(f'{response.status}: {response.reason}: {_decode(body)}')
            return False
    except Exception as e:
        logger.error(f'Exception occurred while patching custom device: {e}')
        return False


def delete_custom_device(conn, api_key, device_id, dry_run=False):
    """
    Deletes a custom device from the ExtraHop platform.

    Returns:
        bool: True if the delete succeeded, False otherwise.
    """
    if dry_run:
        logger.info(f'[DRY RUN] Would delete custom device {device_id} '
                     f'from {conn.hostname}')
        return True

    logger.info(f'Deleting custom device {device_id} from {conn.hostname}')
    try:
        url = f'/api/v1/customdevices/{device_id}'
        headers = {
            'accept': 'application/json',
            'Authorization': f'ExtraHop apikey={api_key}'
        }
        response, body = conn.send_request('DELETE', url, headers)
        if not response:
            logger.error(f'No response received while deleting custom device: {device_id}')
            return False
        if response.status == 204:
            logger.info(f'{response.status}: Custom device {device_id} successfully deleted.')
            return True
        else:
            logger.error(f'{response.status}: {response.reason}: {_decode(body)}')
            return False
    except Exception as e:
        logger.error(f'Exception occurred while deleting custom device: {e}')
        return False


def audit_custom_devices(conn, api_key, summary, output_dir=None,
                         verbose=False, include_criteria=False,
                         include_metrics=False, metric_window_ms=-1209600000):
    """
    Retrieves custom devices from ExtraHop and writes them to a CSV file.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        summary (RunSummary): The run summary tracker.
        output_dir (str or None): Directory to write the audit CSV into.
        verbose (bool): Include additional detail columns.
        include_criteria (bool): Include device criteria columns.
        include_metrics (bool): Include device metric columns.
        metric_window_ms (int): Negative ms offset for metric lookback.
    """
    logger.info(f'Auditing appliance: {conn.hostname}')
    custom_devices = get_custom_devices(conn, api_key, include_criteria)
    if not custom_devices:
        logger.warning(f'No custom devices found on {conn.hostname}. Skipping audit.')
        return

    # Sanitize hostname for safe use in filename
    safe_hostname = ''.join(
        c if c.isalnum() or c in ('-', '.', '_') else '_'
        for c in conn.hostname
    )
    csv_filename = f'custom_devices_audit_{safe_hostname}.csv'
    if output_dir:
        csv_filename = os.path.join(output_dir, csv_filename)

    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['name']
        if verbose:
            fieldnames.extend(['author', 'description', 'disabled',
                               'extrahop_id', 'id', 'mod_time'])
        if include_criteria:
            fieldnames.extend(['ipaddr', 'ipaddr_direction', 'ipaddr_peer',
                               'src_port_min', 'src_port_max',
                               'dst_port_min', 'dst_port_max',
                               'vlan_min', 'vlan_max'])
        if include_metrics:
            fieldnames.extend(['bytes'])

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for custom_device in custom_devices:
            criteria_list = custom_device.get('criteria', []) if include_criteria else [{}]
            if not criteria_list:
                criteria_list = [{}]
            for index, criteria in enumerate(criteria_list):
                device_name = custom_device.get('name', '')
                row = {'name': device_name}
                if verbose:
                    row.update({
                        'author': custom_device.get('author', '') if index == 0 else '',
                        'description': custom_device.get('description', '') if index == 0 else '',
                        'disabled': custom_device.get('disabled', '') if index == 0 else '',
                        'extrahop_id': custom_device.get('extrahop_id', '') if index == 0 else '',
                        'id': custom_device.get('id', '') if index == 0 else '',
                        'mod_time': custom_device.get('mod_time', '') if index == 0 else ''
                    })
                if include_criteria:
                    row.update({
                        'ipaddr': criteria.get('ipaddr', ''),
                        'ipaddr_direction': criteria.get('ipaddr_direction', ''),
                        'ipaddr_peer': criteria.get('ipaddr_peer', ''),
                        'src_port_min': criteria.get('src_port_min', ''),
                        'src_port_max': criteria.get('src_port_max', ''),
                        'dst_port_min': criteria.get('dst_port_min', ''),
                        'dst_port_max': criteria.get('dst_port_max', ''),
                        'vlan_min': criteria.get('vlan_min', ''),
                        'vlan_max': criteria.get('vlan_max', '')
                    })
                if include_metrics:
                    device_info = search_device(conn, api_key, device_name)
                    device_bytes = 0
                    for dev in device_info:
                        if dev.get('role', '') == 'custom':
                            device_metrics = metric_query(conn, api_key, dev.get('id', ''),
                                                              metric_window_ms=metric_window_ms)
                            if device_metrics and 'stats' in device_metrics:
                                for stat in device_metrics['stats']:
                                    values = stat.get('values', [])
                                    if isinstance(values, list):
                                        device_bytes += sum(
                                            v for v in values
                                            if isinstance(v, (int, float))
                                        )
                    row['bytes'] = device_bytes if index == 0 else ''
                writer.writerow(row)
                summary.audited += 1

    logger.info(f'Custom devices successfully written to {csv_filename}')


def create_custom_devices_from_csv(conn, api_key, custom_devices_csv,
                                   summary, patch=False, auto_yes=False,
                                   dry_run=False):
    """
    Reads a CSV file of custom devices, creates them on ExtraHop, and
    optionally patches existing devices with the same name.

    A single custom device can have multiple filter groups (criteria rows).
    The CSV supports this by having multiple rows with the same device name,
    each with different criteria columns. They get merged into one device
    payload with a list of criteria.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        custom_devices_csv (str): Path to the CSV file.
        summary (RunSummary): The run summary tracker.
        patch (bool): If True, patch devices that already exist.
        auto_yes (bool): If True, skip interactive prompts and patch all.
        dry_run (bool): If True, log what would happen without making changes.
    """
    custom_devices = get_custom_devices(conn, api_key, include_criteria=True)

    # Build a lookup of existing custom devices by name -> id
    custom_devices_lookup = {}
    for cd in custom_devices:
        cd_name = cd.get('name', '')
        if cd_name and 'id' in cd:
            custom_devices_lookup[cd_name] = cd['id']

    processed_devices = _parse_csv_to_device_map(custom_devices_csv)
    if not processed_devices:
        return

    # Track whether the user chose "all" for patching across all devices
    confirm_all_patches = auto_yes

    for device_payload in processed_devices.values():
        name = device_payload['name']
        success, response_body = create_custom_device(
            conn, api_key, device_payload, dry_run=dry_run
        )

        if success:
            summary.created += 1
            continue

        # If creation failed, check if it's because the device already exists
        if not response_body:
            logger.error(f'Failed to create device {name} and got no '
                         f'response body. Skipping.')
            summary.failed += 1
            continue

        try:
            parsed_response = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            logger.error(f'Could not parse response body for device '
                         f'{name}: {response_body}')
            summary.failed += 1
            continue

        detail = parsed_response.get('detail', '').strip()
        expected_msg = f'A custom device with the name {name} already exists.'

        if detail != expected_msg:
            logger.error(f'Unexpected error for device {name}: {detail}')
            summary.failed += 1
            continue

        if not patch:
            logger.info(f'Device {name} already exists and --patch not enabled. Skipping.')
            summary.skipped += 1
            continue

        # Device exists and --patch is enabled. Ask user or use "all" / --yes.
        if not confirm_all_patches:
            valid_options = ['yes', 'no', 'all']
            user_input = ''
            while user_input not in valid_options:
                user_input = input(
                    f'Device "{name}" already exists. Patch it? (yes/no/all): '
                ).strip().lower()
                if user_input not in valid_options:
                    print(f"Invalid input. Choose one of: {', '.join(valid_options)}")

            if user_input == 'no':
                logger.info(f'Skipping patch for device {name}.')
                summary.skipped += 1
                continue
            elif user_input == 'all':
                confirm_all_patches = True

        # Look up the device ID and patch
        device_id = custom_devices_lookup.get(name)
        if not device_id:
            logger.error(f'Could not find existing device ID for {name}. Skipping patch.')
            summary.failed += 1
            continue

        # Build patch payload. Remove extrahop_id since the API does not
        # allow it to be changed after the device is created.
        patch_payload = {k: v for k, v in device_payload.items()
                         if k != 'extrahop_id'}
        result = patch_custom_device(
            conn, api_key, device_id, patch_payload, dry_run=dry_run
        )
        if result:
            summary.patched += 1
        else:
            summary.failed += 1


def patch_add_from_csv(conn, api_key, csv_path, summary,
                       auto_yes=False, dry_run=False):
    """
    Appends criteria from a CSV to existing custom devices.

    For each device in the CSV, fetches the device's current criteria from
    the appliance, adds any new criteria from the CSV that aren't already
    present, and PATCHes the device with the combined list.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        csv_path (str): Path to the CSV file with criteria to add.
        summary (RunSummary): The run summary tracker.
        auto_yes (bool): If True, skip interactive prompts.
        dry_run (bool): If True, log what would happen without making changes.
    """
    logger.info(f'Appending criteria from {csv_path} to existing devices...')
    custom_devices = get_custom_devices(conn, api_key, include_criteria=True)
    if not custom_devices:
        logger.warning(f'No custom devices found on {conn.hostname}. '
                       f'Nothing to append to.')
        return

    # Build lookups by name
    devices_by_name = {}
    for cd in custom_devices:
        cd_name = cd.get('name', '')
        if cd_name and 'id' in cd:
            devices_by_name[cd_name] = cd

    csv_devices = _parse_csv_to_device_map(csv_path)
    if not csv_devices:
        return

    confirm_all = auto_yes

    for name, csv_payload in csv_devices.items():
        existing = devices_by_name.get(name)
        if not existing:
            logger.info(f'Device {name} not found on appliance. Skipping.')
            summary.skipped += 1
            continue

        device_id = existing['id']
        existing_criteria = existing.get('criteria', [])
        new_criteria = csv_payload.get('criteria', [])

        # Deduplicate: only add criteria not already present
        to_add = []
        for nc in new_criteria:
            already_exists = any(
                _criteria_match(ec, nc) and _criteria_match(nc, ec)
                for ec in existing_criteria
            )
            if already_exists:
                logger.info(f'Criteria already exists on {name}, skipping: {nc}')
            else:
                to_add.append(nc)

        if not to_add:
            logger.info(f'No new criteria to add for {name}. Skipping.')
            summary.skipped += 1
            continue

        combined = existing_criteria + to_add

        if not confirm_all:
            valid_options = ['yes', 'no', 'all']
            user_input = ''
            while user_input not in valid_options:
                user_input = input(
                    f'Add {len(to_add)} criteria to "{name}" '
                    f'({len(existing_criteria)} existing)? (yes/no/all): '
                ).strip().lower()
                if user_input not in valid_options:
                    print(f"Invalid input. Choose one of: {', '.join(valid_options)}")
            if user_input == 'no':
                logger.info(f'Skipping append for device {name}.')
                summary.skipped += 1
                continue
            elif user_input == 'all':
                confirm_all = True

        logger.info(f'Appending {len(to_add)} criteria to {name} '
                     f'({len(existing_criteria)} existing -> '
                     f'{len(combined)} total)')

        patch_payload = {'criteria': combined}
        result = patch_custom_device(
            conn, api_key, device_id, patch_payload, dry_run=dry_run
        )
        if result:
            summary.patched += 1
        else:
            summary.failed += 1


def patch_remove_from_csv(conn, api_key, csv_path, summary,
                          auto_yes=False, dry_run=False):
    """
    Removes criteria from existing custom devices based on a CSV.

    For each device in the CSV, fetches the device's current criteria from
    the appliance, removes any criteria that match the CSV rows, and PATCHes
    the device with the remaining list.

    A match means every field in the CSV row equals the same field in the
    existing criteria. You can specify just ipaddr to match any criteria
    with that IP, or include more fields for a tighter match.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        csv_path (str): Path to the CSV file with criteria to remove.
        summary (RunSummary): The run summary tracker.
        auto_yes (bool): If True, skip interactive prompts.
        dry_run (bool): If True, log what would happen without making changes.
    """
    logger.info(f'Removing criteria from {csv_path} from existing devices...')
    custom_devices = get_custom_devices(conn, api_key, include_criteria=True)
    if not custom_devices:
        logger.warning(f'No custom devices found on {conn.hostname}. '
                       f'Nothing to remove from.')
        return

    devices_by_name = {}
    for cd in custom_devices:
        cd_name = cd.get('name', '')
        if cd_name and 'id' in cd:
            devices_by_name[cd_name] = cd

    csv_devices = _parse_csv_to_device_map(csv_path)
    if not csv_devices:
        return

    confirm_all = auto_yes

    for name, csv_payload in csv_devices.items():
        existing = devices_by_name.get(name)
        if not existing:
            logger.info(f'Device {name} not found on appliance. Skipping.')
            summary.skipped += 1
            continue

        device_id = existing['id']
        existing_criteria = existing.get('criteria', [])
        remove_targets = csv_payload.get('criteria', [])

        # Find which existing criteria match a removal target
        remaining = []
        removed = []
        for ec in existing_criteria:
            matched = any(_criteria_match(ec, rt) for rt in remove_targets)
            if matched:
                removed.append(ec)
            else:
                remaining.append(ec)

        if not removed:
            logger.info(f'No matching criteria to remove for {name}. Skipping.')
            summary.skipped += 1
            continue

        if not confirm_all:
            valid_options = ['yes', 'no', 'all']
            user_input = ''
            while user_input not in valid_options:
                user_input = input(
                    f'Remove {len(removed)} criteria from "{name}" '
                    f'({len(existing_criteria)} existing -> '
                    f'{len(remaining)} remaining)? (yes/no/all): '
                ).strip().lower()
                if user_input not in valid_options:
                    print(f"Invalid input. Choose one of: {', '.join(valid_options)}")
            if user_input == 'no':
                logger.info(f'Skipping removal for device {name}.')
                summary.skipped += 1
                continue
            elif user_input == 'all':
                confirm_all = True

        logger.info(f'Removing {len(removed)} criteria from {name} '
                     f'({len(existing_criteria)} existing -> '
                     f'{len(remaining)} remaining)')

        if not remaining:
            logger.warning(f'All criteria would be removed from {name}. '
                           f'The device will have no filter criteria.')

        patch_payload = {'criteria': remaining}
        result = patch_custom_device(
            conn, api_key, device_id, patch_payload, dry_run=dry_run
        )
        if result:
            summary.patched += 1
        else:
            summary.failed += 1


def delete_custom_devices_from_csv(conn, api_key, custom_devices_csv,
                                   summary, dry_run=False):
    """
    Deletes custom devices listed in a CSV file from the ExtraHop platform.

    Parameters:
        conn (ConnectionManager): The connection manager.
        api_key (str): The API key for authentication.
        custom_devices_csv (str): Path to the CSV file with device names.
        summary (RunSummary): The run summary tracker.
        dry_run (bool): If True, log what would happen without making changes.
    """
    logger.info(f'Deleting custom devices listed in {custom_devices_csv}...')

    custom_devices = get_custom_devices(conn, api_key, include_criteria=True)
    if not custom_devices:
        logger.warning(f'No custom devices found on {conn.hostname}. Nothing to delete.')
        return

    custom_devices_lookup = {
        cd['name']: cd['id']
        for cd in custom_devices
        if 'name' in cd and 'id' in cd
    }

    with _open_csv(custom_devices_csv) as f:
        for row in csv.DictReader(f):
            name = row.get('name', '').strip()
            if not name:
                continue
            device_id = custom_devices_lookup.get(name)
            logger.debug(f'name: {name} | id: {device_id}')
            if not device_id:
                logger.info(f'No custom device found with name: {name}. Skipping.')
                summary.skipped += 1
                continue
            result = delete_custom_device(conn, api_key, device_id, dry_run=dry_run)
            if result:
                summary.deleted += 1
            else:
                summary.failed += 1


def main():
    parser = argparse.ArgumentParser(description='Manage ExtraHop Custom Devices')
    parser.add_argument('--appliances', type=str, required=True,
                        help='Path to CSV file containing appliance hostnames '
                             'and API keys')
    parser.add_argument('--create', type=str,
                        help='Path to CSV file containing custom devices to create')
    parser.add_argument('--delete', type=str,
                        help='Path to CSV file containing custom devices to delete')
    parser.add_argument('--patch', action='store_true',
                        help='If enabled, overwrite existing custom devices '
                             'when found (replaces all criteria)')
    parser.add_argument('--patch-add', type=str, default=None,
                        help='Path to CSV file with criteria to append to '
                             'existing devices (does not replace existing '
                             'criteria)')
    parser.add_argument('--patch-remove', type=str, default=None,
                        help='Path to CSV file with criteria to remove from '
                             'existing devices')
    parser.add_argument('--yes', action='store_true',
                        help='Skip interactive prompts and auto-confirm all '
                             'patch operations')
    parser.add_argument('--dry-run', action='store_true',
                        help='Log what would happen without making any changes')
    parser.add_argument('--audit', action='store_true',
                        help='Audit custom devices on the appliances')
    parser.add_argument('--verbose', action='store_true',
                        help='Include additional details in audit CSV output')
    parser.add_argument('--include_criteria', action='store_true',
                        help='Include custom device criteria in audit output')
    parser.add_argument('--include_metrics', action='store_true',
                        help='Include custom device metrics in audit output')
    parser.add_argument('--metric-window', type=int, default=14,
                        help='Metric lookback window in days (default: 14)')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Directory to write output files into '
                             '(default: current directory)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification. Required '
                             'for appliances using self-signed certificates.')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')

    args = parser.parse_args()

    setup_logging(args.log_level)

    logger.info('Initializing Custom Device Manager...')

    if args.no_verify_ssl:
        logger.warning('SSL certificate verification is disabled.')

    if args.dry_run:
        logger.info('[DRY RUN MODE] No changes will be made.')

    logger.debug(f'Args: audit={args.audit}, create={args.create}, '
                 f'delete={args.delete}, patch={args.patch}, '
                 f'patch_add={args.patch_add}, patch_remove={args.patch_remove}, '
                 f'dry_run={args.dry_run}, verbose={args.verbose}, '
                 f'log_level={args.log_level}')

    if not any([args.audit, args.create, args.delete,
                args.patch_add, args.patch_remove]):
        parser.error('At least one action is required: --audit, --create, '
                     '--delete, --patch-add, or --patch-remove')

    # Validate file paths before doing anything
    for path_arg, label in [(args.appliances, '--appliances'),
                            (args.create, '--create'),
                            (args.delete, '--delete'),
                            (args.patch_add, '--patch-add'),
                            (args.patch_remove, '--patch-remove')]:
        if path_arg and not os.path.isfile(path_arg):
            parser.error(f'{label} file not found: {path_arg}')

    # Validate and create output directory if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        logger.info(f'Output directory: {args.output_dir}')

    # Convert days to negative millisecond offset
    if args.metric_window < 1:
        parser.error('--metric-window must be at least 1 day')
    metric_window_ms = -(args.metric_window * 86400000)

    verify_ssl = not args.no_verify_ssl
    summary = RunSummary()

    logger.info(f'Reading {args.appliances}...')
    with _open_csv(args.appliances) as csv_file:
        appliances = list(csv.DictReader(csv_file))
        logger.debug(f'Loaded {len(appliances)} appliance(s)')

    for appliance in appliances:
        hostname = appliance.get('hostname', '').strip()
        api_key = appliance.get('api_key', '').strip()

        if not hostname or not api_key:
            logger.warning(f'Skipping appliance with missing hostname or '
                           f'api_key: hostname={hostname!r}')
            continue

        logger.info(f'Processing tasks on appliance: {hostname}')
        conn = ConnectionManager(hostname, verify_ssl=verify_ssl)
        if not conn.connect():
            logger.error(f'Could not connect to {hostname}. Skipping.')
            continue

        if args.audit:
            audit_custom_devices(
                conn, api_key, summary,
                output_dir=args.output_dir,
                verbose=args.verbose,
                include_criteria=args.include_criteria,
                include_metrics=args.include_metrics,
                metric_window_ms=metric_window_ms
            )
        if args.create:
            create_custom_devices_from_csv(
                conn, api_key, args.create, summary,
                patch=args.patch,
                auto_yes=args.yes,
                dry_run=args.dry_run
            )
        if args.patch_add:
            patch_add_from_csv(
                conn, api_key, args.patch_add, summary,
                auto_yes=args.yes,
                dry_run=args.dry_run
            )
        if args.patch_remove:
            patch_remove_from_csv(
                conn, api_key, args.patch_remove, summary,
                auto_yes=args.yes,
                dry_run=args.dry_run
            )
        if args.delete:
            delete_custom_devices_from_csv(
                conn, api_key, args.delete, summary,
                dry_run=args.dry_run
            )

    summary.log()


if __name__ == '__main__':
    main()
