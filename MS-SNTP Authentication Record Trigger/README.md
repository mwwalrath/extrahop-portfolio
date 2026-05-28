# MS-SNTP Authentication Record Trigger

ExtraHop trigger that parses MS-SNTP authentication trailers from NTPv3 traffic and commits enriched records for timeroasting detection.

## Problem

[Timeroasting](https://github.com/SecuraBV/Timeroast) (Secura, 2023) is a credential-theft technique that sends crafted NTPv3 requests to Windows Domain Controllers. Each request includes an AD computer account RID in the NTP Key ID field. The DC responds with an MD5 MAC derived from the account's NTLM password hash -- material for offline cracking. The attack is unauthenticated, runs over UDP/123, and produces no Windows event logs.

ExtraHop classifies NTP traffic and exposes standard header fields (mode, version, stratum, timestamps), but does not parse the MS-SNTP authentication trailer. The Key ID (RID) and MAC are not available in built-in records or metrics. Without payload-level extraction, timeroasting requests are indistinguishable from normal NTP traffic.

## What This Trigger Does

Parses the NTPv3 authentication trailer at offset 48, extracts the Key ID as a little-endian uint32 (the AD RID) and the MAC, classifies the request based on the RID value, and commits an enriched record to the ExtraHop recordstore. Records are exported to a SIEM for correlation and detection.

The trigger does not implement detection logic. It provides the data. Detection thresholds, time windows, and alerting are owned by the SOC team in the SIEM.

## Design Decisions

**Dual-event architecture.** The trigger subscribes to both `NTP_MESSAGE` and `UDP_PAYLOAD`. `NTP_MESSAGE` fires when ExtraHop classifies the flow as NTP. `UDP_PAYLOAD` catches unclassified UDP on port 123, including unanswered single-packet flows that ExtraHop may never classify. Timeroasting often produces unanswered requests (the attacker may not wait for responses), so the `UDP_PAYLOAD` path is critical.

**`Flow.sender` / `Flow.receiver` instead of `Flow.client` / `Flow.server`.** Unanswered UDP flows may never establish the client/server relationship in ExtraHop. `sender`/`receiver` reflects the actual packet direction and is always available regardless of flow state.

**Little-endian Key ID read.** MS-SNTP stores the RID as a little-endian uint32. ExtraHop's `Buffer.unpack('I')` reads big-endian by default. The trigger uses `'<I'` for the correct byte order.

**Defensive length check (>= 56 bytes, not exactly 68).** Standard MS-SNTP uses a 16-byte MD5 MAC (68-byte packet). The relaxed check also catches 20-byte SHA1 MACs (72 bytes) and non-standard lengths from modified attack tools. NTPv4 is excluded by the version check, so extension field walking is unnecessary.

**No `skipExtensions()`.** MS-SNTP is NTPv3 only. NTPv3 has no extension fields. The auth trailer is always at offset 48.

**Helper functions defined before the event router.** Per [ExtraHop trigger best practices](https://docs.extrahop.com/current/triggers-best-practices/): "Define helper functions at the top of the trigger script to improve readability and help the ExtraHop system better understand and run your code."

**No session table, no detection logic.** The trigger's job is payload extraction and record enrichment. Detection is a SIEM concern. This keeps the trigger stateless -- each packet is processed independently with zero cross-packet memory.

## Record Schema

Fields added by the trigger (ExtraHop auto-populates `_time`, `clientAddr`, `serverAddr`):

| Field | Type | Description |
|---|---|---|
| `authPresent` | boolean | Auth trailer found |
| `authKeyId` | number | AD RID from Key ID field (LE uint32) |
| `authKeyIdHex` | string | Key ID as 8-char hex |
| `authMacHex` | string | MAC as hex |
| `authMacLen` | number | MAC length (16 = MD5, 20 = SHA1) |
| `authAlgGuess` | string | `'MD5'`, `'SHA1'`, or `'unknown(N)'` |
| `isTimeroastCandidate` | boolean | `true` when `authKeyId >= 500` |
| `timeroastReason` | string | Human-readable classification |
| `triggerVersion` | string | Trigger version |
| `triggerEvent` | string | `'NTP_MESSAGE'` or `'UDP_PAYLOAD'` |

## Setup

1. Create trigger with events: `NTP_MESSAGE`, `UDP_PAYLOAD`
2. `UDP_PAYLOAD` advanced options: **Run trigger on all UDP packets** = enabled, **Server Port Range** = 123-123
3. Assign to Domain Controllers
4. Set `DEBUG_MODE = true`, verify debug log output
5. Set `DEBUG_MODE = false`, `COMMIT_NTP_RECORDS = true` for production

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DEBUG_MODE` | `true` | Log parsed packets, commit nothing |
| `COMMIT_NTP_RECORDS` | `false` | Write records to recordstore |
| `ONLY_COMMIT_IF_AUTH` | `false` | Skip records where auth extraction fails |
| `RID_FLOOR` | `500` | Key IDs below this are built-in AD accounts |

## Limitations

- Requires network visibility to DC port 123 (span/tap feeding the sensor).
- Client requests only. Does not parse server responses.
- NTPv3 only. A hypothetical NTPv4-based attack would not match.
- Legitimate MS-SNTP auth from domain-joined machines also produces records (Key IDs >= 500). Filter in your SIEM.
- The >= 56 byte check accepts any NTPv3 mode-3 packet with 8+ bytes after the header. False positives from non-NTP UDP on port 123 are theoretically possible but extremely unlikely.

## References

- [Timeroasting -- Secura](https://github.com/SecuraBV/Timeroast)
- [ExtraHop Trigger API Reference](https://docs.extrahop.com/current/extrahop-trigger-api/)
- [ExtraHop Triggers Best Practices](https://docs.extrahop.com/current/triggers-best-practices/)
- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

## License

MIT
