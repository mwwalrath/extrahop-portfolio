# RevealX 360 Audit Log Source Aggregator

A small Python tool for scoping a [RevealX 360 Allow List](https://docs.extrahop.com/current/rx360-setup-admin/#configure-an-allow-list)
from real activity data.

[![tests](https://github.com/mwwalrath/ExtraHop/rx360-auditlog-sources/actions/workflows/test.yml/badge.svg)](https://github.com/mwwalrath/ExtraHop/rx360-auditlog-sources/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)

## Why this exists

The RevealX 360 Allow List restricts UI and REST API access to a set of
source IPs and CIDR blocks. Before turning it on, you need to know which
source networks are actually authenticating against your tenant or you
risk locking out legitimate users and integrations.

The audit log captures this data, but the native UI does not aggregate it.
With the constant background noise of scanner traffic against the public
OAuth endpoint, manually walking 30 days of audit entries to identify
legitimate sources is not practical at any reasonable tenant size.

This script pulls the audit log via REST API, classifies each event
(UI login, REST API auth, post-auth operation), and aggregates source
IPs into /24 buckets. The output CSV separates legitimate traffic from
scanner noise and makes the Allow List scoping decision tractable.

## What I learned building this

A few things that shaped the design:

**The structured `src_ip` field is empty for UI Login events.** For UI
logins, the source IP is buried in the free-text `details` field
("Login succeeded from `<IP>` ..."). The script falls back to a regex
extraction when the structured field is missing. Missing this fact
silently drops all UI activity from the analysis.

**Post-authentication operations lose external source IP.** For dashboard
edits, bundle applies, trigger changes, and similar, the audit log
records only the AWS Network Load Balancer internal hop (RFC 6598,
`100.127.0.0/24`), not the real client. The Allow List enforces at the
auth boundary so this does not affect its function, but it does mean the
audit log is not a reliable forensic tool for post-auth attribution.

**Corporate proxies can hide the real public source.** If traffic to
RevealX 360 routes through a proxy that injects X-Forwarded-For with
internal client IPs, those appear in the output tagged `private` or
`cgnat`. The cloud edge sees the proxy's public egress, which the audit
log does not expose. Customers need their network team to confirm public
egress IPs separately.

**The public OAuth endpoint is constantly scanned.** While testing
against a single tenant, I observed tens of thousands of failed
authentication attempts per week from rotating AWS, Linode, and
DigitalOcean IPs, with methodical two-hour-per-IP rotation patterns
consistent with commercial credential-stuffing infrastructure. This is
exactly the noise floor an Allow List eliminates and exactly why you
need a tool to separate it from real traffic.

## Example output

| cidr | address_class | events_total | ui_success | api_success | api_fail | distinct_users |
|---|---|---|---|---|---|---|
| 203.0.113.0/24 | public | 10201 | 0 | 0 | 10201 | 0 |
| 10.10.20.0/24 | private | 972 | 99 | 873 | 0 | 37 |
| 100.127.0.0/24 | cgnat | 24 | 0 | 1 | 0 | 10 |
| 198.51.100.0/24 | public | 12 | 0 | 0 | 12 | 0 |
| 192.0.2.0/24 | public | 2 | 2 | 0 | 0 | 1 |

Row 1 is the scanner pattern: high `api_fail`, zero distinct users,
exclusively failed auth attempts. Row 2 is corporate-network traffic
arriving via a proxy that injects internal IPs into XFF (the real
public source is the proxy's egress, which is not visible here). Row 3
is the AWS NLB internal hop, recorded for post-auth operations. Row 4
is a smaller-scale scanner. Row 5 is a legitimate admin source and an
Allow List candidate.

## Requirements

- Python 3.10 or newer
- REST API credential on the target tenant with at minimum System
  Administration privilege
- Outbound HTTPS to the RevealX 360 API endpoint

## Setup

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # PowerShell on Windows
# source .venv/bin/activate      # bash on macOS or Linux
pip install -r requirements.txt
```

Create `.env` in the same directory (UTF-8, no BOM):

```
EH_API_HOST=<tenant>.api.cloud.extrahop.com
EH_API_ID=<credential id>
EH_API_SECRET=<credential secret>
```

`EH_API_HOST` is the API hostname (with `.api.`) shown on the API Access
page, with the trailing `/oauth2/token` stripped. Not the UI URL.
`HTTPS_PROXY` and `REQUESTS_CA_BUNDLE` are honored by the underlying
`requests` library.

## Run

```
python aggregate_auditlog_sources.py --lookback-days 7
```

Flags:

- `--lookback-days N` - days to scan back. Default 30.
- `--output PATH` - output CSV path. Default `auditlog_sources.csv`.
- `--force` - overwrite output if it exists.
- `--page-size N` / `--max-pages N` - pagination tuning. Defaults 1000 / 200.
  If the run hits `--max-pages` before the cutoff, a `WARNING` is printed
  and the output is incomplete.

## Output columns

CSV sorted by `events_total` descending. Treat the output as sensitive. It
contains usernames and source IP topology.

| Column | Meaning |
|---|---|
| `cidr` | The /24 source network |
| `address_class` | `public`, `private`, `cgnat`, `loopback`, `link_local`, `reserved`, `invalid`. The Allow List enforces at the cloud edge against public source IPs only. Non-public values here are XFF-injected or NLB internal hops. |
| `events_total` | Total audit entries from this /24 within the window |
| `ui_success` / `ui_fail` | UI Login outcomes |
| `api_success` / `api_fail` | REST API token request outcomes |
| `other` | Post-auth operations where the audit log did not preserve the external client IP |
| `distinct_users`, `users` | Identity counts and real (non-Unknown) usernames |
| `operations` | Distinct audit log operation types seen |
| `first_seen`, `last_seen` | UTC timestamps |

## Caveats

The event classifier (`category` and `outcome`) is a string-match
heuristic on the `operation` and `details` fields. Older firmware
versions or alternate identity providers may produce strings that
misclassify.

Forged X-Forwarded-For headers on requests to the public OAuth endpoint
will produce misleading source IPs in this output. They do not affect
the Allow List itself, which enforces against the actual TCP source
before XFF processing.

## After running

REST API credentials on RevealX 360 do not expire automatically. Delete
the credential on the API Access page when finished.

## Development

```
pip install -r requirements-dev.txt
pytest
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE).
