# ExtraHop Custom Device Manager

## Overview

This script manages **ExtraHop Custom Devices** by interacting with the ExtraHop REST API. It enables auditing, retrieving device metrics, searching, creating, patching, and deleting custom devices using data from CSV files.

The script logs detailed information about operations, with robust error-handling mechanisms to ensure traceability of issues.

## Features

- **Audit Custom Devices:** Retrieve and export details of existing custom devices from ExtraHop appliances.
- **Search for Devices:** Search for devices by name using the ExtraHop REST API.
- **Metric Querying:** Query bytes for custom devices.
- **Create Custom Devices:** Create custom devices on ExtraHop appliances using data from a CSV file. Supports multiple filter groups (criteria) per device by repeating the device name across CSV rows.
- **Patch Custom Devices (Replace):** Overwrite all criteria on existing custom devices. Supports interactive confirmation, batch updating with `--yes`, and safe preview with `--dry-run`.
- **Patch Custom Devices (Append):** Add new criteria to existing devices without removing what's already there. Automatically skips duplicates.
- **Patch Custom Devices (Remove):** Remove specific criteria from existing devices by matching on the fields you specify.
- **Delete Custom Devices:** Delete custom devices based on data from a CSV file.
- **Dry Run Mode:** Preview all create, patch, and delete operations without making any changes.
- **Run Summary:** Displays a summary of operations at the end of each run (created, patched, deleted, skipped, failed).
- **Automatic Reconnection:** Recovers from dropped connections mid-run without losing progress.

## Requirements

- Python 3.6+
- ExtraHop REST API access
- ExtraHop API key for authentication

## Setup

1. Clone this repository or copy the script into a new `.py` file.
2. No external dependencies are required. The script uses only Python standard library modules.
3. Ensure your environment has access to the ExtraHop appliance with the necessary API permissions.

## Logging

The script generates a log file in the `logs` directory, named based on the script name and current datetime. Log output is also printed to the console in real time. Logs provide information about the flow of operations, successes, and errors encountered.

## Usage

The script is used to audit and manage custom devices on ExtraHop appliances. It can be invoked via command-line with different options for auditing, creating, patching, deleting, and more.

### Command-Line Arguments

| Argument             | Description                                                                                 |
|----------------------|---------------------------------------------------------------------------------------------|
| `--appliances`       | **(Required)** Path to the CSV file containing appliance hostnames and API keys.            |
| `--audit`            | Audit the existing custom devices on the appliance(s).                                      |
| `--verbose`          | Include additional details in the CSV output for auditing purposes.                         |
| `--include_criteria` | Include the custom device criteria while auditing.                                          |
| `--include_metrics`  | Include custom device metrics in the audit output.                                          |
| `--create`           | Path to the CSV file containing custom devices to be created.                               |
| `--patch`            | Used with `--create`. Replaces all criteria on existing devices with what's in the CSV.     |
| `--patch-add`        | Path to CSV file with criteria to **append** to existing devices. Does not remove existing criteria. |
| `--patch-remove`     | Path to CSV file with criteria to **remove** from existing devices.                         |
| `--yes`              | Skip interactive prompts and auto-confirm all patch operations.                             |
| `--dry-run`          | Log what would happen without making any changes to the appliance.                          |
| `--delete`           | Path to the CSV file containing custom devices to be deleted.                               |
| `--output-dir`       | Directory to write output files into (default: current directory).                          |
| `--metric-window`    | Metric lookback window in days (default: 14). Used with `--include_metrics`.                |
| `--no-verify-ssl`    | Disable SSL certificate verification. Required for self-signed certificates.                |
| `--log-level`        | Set the logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Defaults to `INFO`.|

### Patch Modes Compared

The script supports three distinct ways to update device criteria:

| Mode | Flag | What it does | Use when... |
|------|------|-------------|-------------|
| **Replace** | `--create devices.csv --patch` | Overwrites all criteria with the CSV contents | You want the CSV to be the single source of truth |
| **Append** | `--patch-add criteria.csv` | Adds new criteria while keeping existing ones | You need to add a subnet to devices that already have filters |
| **Remove** | `--patch-remove criteria.csv` | Removes matching criteria while keeping the rest | You need to retire a subnet from devices |

### Example Usage

1. **Auditing Custom Devices:**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --audit --verbose --include_criteria --include_metrics
    ```

    This command will audit custom devices from the ExtraHop appliance(s) listed in `appliances.csv`.

2. **Auditing to a Specific Output Directory:**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --audit --verbose --output-dir ./reports
    ```

    Writes the audit CSV into the `./reports` directory instead of the current directory.

3. **Creating Custom Devices from CSV:**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --create custom_devices.csv
    ```

    This command will create custom devices on ExtraHop appliance(s) using the list provided in `custom_devices.csv`.

4. **Patching Existing Custom Devices (Replace, Interactive):**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --create custom_devices.csv --patch
    ```

    This command will create custom devices and prompt you before patching each one that already exists. You can respond `yes`, `no`, or `all` at each prompt.

5. **Patching All Without Prompts (Replace):**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --create custom_devices.csv --patch --yes
    ```

    Same as above, but skips all prompts and patches every existing device automatically. Useful for automation and scripted workflows.

6. **Adding a Subnet to Existing Devices (Append):**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --patch-add new_subnets.csv --yes
    ```

    Fetches each device's current criteria from the appliance, appends any new criteria from the CSV, and PATCHes the device. Criteria that already exist on the device are automatically skipped. This is the recommended approach for adding a subnet across many devices.

7. **Removing a Subnet from Existing Devices (Remove):**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --patch-remove old_subnets.csv --yes
    ```

    Fetches each device's current criteria, removes any that match the CSV rows, and PATCHes the device with the remaining criteria. Matching is flexible — if your CSV only specifies `ipaddr`, it matches any criteria on the device that has that IP, regardless of other fields like ports or direction.

8. **Dry Run (Preview Changes):**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --patch-add new_subnets.csv --yes --dry-run
    ```

    Logs every operation that *would* happen, without touching the API. Works with all modes: `--create`, `--patch-add`, `--patch-remove`, and `--delete`.

9. **Deleting Custom Devices from CSV:**

    ```sh
    python custom_device_manager.py --appliances appliances.csv --delete custom_devices_to_delete.csv
    ```

    This command will delete custom devices listed in `custom_devices_to_delete.csv`.

### Typical Workflow: Adding a Subnet to Custom Devices

```sh
# 1. Snapshot current state
python custom_device_manager.py --appliances appliances.csv \
  --audit --verbose --include_criteria --output-dir ./before

# 2. Prepare a CSV with just the new criteria
#    name,ipaddr
#    Seattle,10.50.0.0/24
#    Portland,10.50.1.0/24
#    ... (one row per device)

# 3. Preview
python custom_device_manager.py --appliances appliances.csv \
  --patch-add new_subnets.csv --yes --dry-run

# 4. Execute
python custom_device_manager.py --appliances appliances.csv \
  --patch-add new_subnets.csv --yes

# 5. Verify
python custom_device_manager.py --appliances appliances.csv \
  --audit --verbose --include_criteria --output-dir ./after
```

### CSV File Format

The script works with CSV files to load appliance and custom device information. CSV files saved from Excel with a BOM (byte order mark) are handled automatically.

#### Appliances CSV

| hostname    | api_key |
|-------------|---------|

#### Custom Devices CSV (Create/Patch/Patch-Add/Patch-Remove)

Each row represents one filter group (criteria) for a custom device. To define multiple filter groups for the same device, use multiple rows with the same `name`.

| name | description | disabled | extrahop_id | ipaddr | ipaddr_direction | ipaddr_peer | src_port_min | src_port_max | dst_port_min | dst_port_max | vlan_min | vlan_max |
|------|-------------|----------|-------------|--------|------------------|-------------|--------------|--------------|--------------|--------------|----------|----------|

**Column notes:**

- `name` **(required):** The friendly name for the custom device.
- `description` *(optional):* A description of the custom device.
- `disabled` *(optional):* Set to `true` to create the device in a disabled state. Defaults to `false`.
- `extrahop_id` *(optional):* A custom unique identifier. If omitted, the API generates one from the device name. Cannot be changed after creation.
- `author` *(optional):* Creator name. Defaults to `API Automation` if omitted.
- `ipaddr`: IP address or CIDR block to match (e.g., `192.168.0.0/26`).
- `ipaddr_direction`: Direction of traffic to match. Valid values: `any`, `src`, `dst`.
- `ipaddr_peer`: Peer IP address. Only valid when `ipaddr` is set and `ipaddr_direction` is not `any`.
- `src_port_min`, `src_port_max`: Source port range (1-65535).
- `dst_port_min`, `dst_port_max`: Destination port range (1-65535).
- `vlan_min`, `vlan_max`: VLAN range.

**Example: Device with multiple filter groups**

| name    | description       | ipaddr           |
|---------|-------------------|------------------|
| Seattle | Washington office | 192.168.0.0/26   |
| Seattle | Washington office | 192.168.0.64/27  |
| Seattle | Washington office | 192.168.0.96/30  |

This creates a single custom device named "Seattle" with three CIDR blocks.

**Example: Minimal CSV for --patch-add (just the new subnet)**

| name    | ipaddr           |
|---------|------------------|
| Seattle | 10.50.0.0/24     |
| Portland| 10.50.1.0/24     |

You only need to include the criteria you want to add. Existing criteria stay untouched.

**Example: Minimal CSV for --patch-remove**

| name    | ipaddr           |
|---------|------------------|
| Seattle | 10.50.0.0/24     |

Removes any criteria on "Seattle" where `ipaddr` is `10.50.0.0/24`. If the device has additional fields on that criteria (like `dst_port_min`), it still matches because the CSV fields are a subset.

#### Custom Devices CSV (Delete)

| name |
|------|

### How --patch-remove Matching Works

When removing criteria, the script checks every field in your CSV row against the existing criteria on the device. A match means every field in the CSV equals the corresponding field on the existing criteria.

This lets you be as broad or specific as you want:

- **Broad:** CSV has only `ipaddr: 10.0.0.0/24` → removes any criteria with that IP, regardless of ports, direction, or VLANs.
- **Specific:** CSV has `ipaddr: 10.0.0.0/24` and `dst_port_min: 80` → only removes criteria where both fields match.

## Validation

The script validates input before making API calls:

- **File paths** are checked before any work starts.
- **Port values** are validated against the API range of 1-65535.
- **`ipaddr_peer`** is rejected if `ipaddr` is missing or `ipaddr_direction` is `any`, per the API spec.
- **Integer fields** (ports, VLANs) are validated and non-numeric values are skipped with a warning.
- **Empty names** in CSV rows are skipped with a warning.
- **`extrahop_id`** is automatically stripped from PATCH payloads since the API does not allow it to be changed after creation.
- **Duplicate criteria** are automatically skipped during `--patch-add` operations.

## Error Handling

The script contains mechanisms to catch and log exceptions, including HTTP error responses and unexpected situations. The `ConnectionManager` automatically reconnects on failure, so a dropped connection mid-run doesn't lose progress. Refer to the generated logs and the console output to troubleshoot issues.

## Dependencies

The script uses only Python standard library modules:

- **argparse**: For parsing command-line arguments.
- **http.client**: To interact with the ExtraHop REST API.
- **csv**: For handling CSV files used to store and retrieve appliance and custom device information.
- **logging**: For logging the execution details and errors.
- **ssl**: To manage SSL/TLS contexts for HTTPS connections (verifies certificates by default).

## SSL Certificate Verification

By default the script verifies SSL certificates when connecting to ExtraHop appliances. Many deployments use self-signed certificates, so you can disable verification with `--no-verify-ssl`:

```sh
python custom_device_manager.py --appliances appliances.csv --audit --no-verify-ssl
```

## Testing

The project includes unit tests for the core parsing and matching logic. Run them with:

```sh
python -m pytest test_custom_device_manager.py -v
```

No ExtraHop appliance is needed to run the tests.

## Disclaimer

This script is provided as-is with no warranty. Please test it in a non-production environment before running on live systems. Use `--dry-run` to preview changes before committing them.

## License

BSD 2-Clause License. See [LICENSE](../LICENSE).
