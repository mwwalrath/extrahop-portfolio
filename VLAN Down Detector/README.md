# VLAN Down Detector v5.1.0

**Trigger for ExtraHop Reveal(x)**
Detects when active VLANs fall off the data feed. Three monitoring tiers (critical, standard, low_value) with independent thresholds and refire intervals. Fires recovery updates when VLANs return.

---

## What it does

The trigger monitors which VLANs are actively passing packets through the ExtraHop sensor. When a VLAN that has been consistently active suddenly goes silent, the trigger commits a custom detection to Reveal(x). When the VLAN recovers, a follow-up update is consolidated into the same detection with the total downtime.

It answers a simple question: "Is every VLAN that should be on the wire still on the wire?"

---

## Why it exists

ExtraHop has no built-in detection for data feed loss at the VLAN level. If a TAP fails, a SPAN port drops, or a routing change silently removes a VLAN from the sensor's view, there's no native alert. This trigger fills that gap.

By default the trigger fires a performance detection (no risk score). A one-line config switch (`DETECTION_CATEGORY = 'security'`) changes it to a security detection with a graduated risk score for SOC pipeline routing. See the configuration reference below.

---

## Tiered monitoring

VLANs are assigned to one of three tiers, each with independent thresholds and refire intervals.

| Tier | Default Threshold | Default Refire | Use Case |
|------|-------------------|----------------|----------|
| **critical** | 10 cycles (5 min) | 60 cycles (30 min) | Core infrastructure VLANs that should never be down |
| **standard** | 120 cycles (1 hour) | 120 cycles (1 hour) | Normal production VLANs (default for all discovered VLANs) |
| **low_value** | 360 cycles (3 hours) | 360 cycles (3 hours) | VLANs with intermittent or low-frequency traffic |

Tier resolution: if a VLAN is in `CRITICAL_VLAN_IDS`, it's critical. If it's in `LOW_VALUE_VLAN_IDS`, it's low_value. Everything else (including all dynamically discovered VLANs) is standard.

Critical VLANs bypass the 7-day discovery check entirely and are always monitored, even before the first API discovery completes. `VLAN_EXCLUDE_IDS` overrides any tier.

---

## Three-phase architecture

The trigger runs on three ExtraHop events that work together on a coordinated 30-second cycle.

### Phase 1: VLAN Discovery (TIMER_30SEC + REMOTE_RESPONSE)

Every 5 minutes, the trigger queries the ExtraHop REST API to build a list of active VLANs:

1. `GET /api/v1/networks/0/vlans` retrieves all known VLANs from the sensor.
2. The response is filtered through `VLAN_EXCLUDE_IDS` to remove suppressed VLANs.
3. `POST /api/v1/metrics` requests 7 days of hourly packet counts for the remaining VLANs. Uses `cycle: '1hr'` explicitly so the bucket count is predictable.
4. A VLAN must have traffic in every hourly bucket across the full 7-day window to qualify as "active." The expected bucket count is `(7 * 24) + 1 = 169`.
5. The active list is stored in the session table as a pipe-delimited string (e.g. `|100|200|300|`) with a 10-minute expiry.

### Phase 2: Traffic Observation (METRIC_RECORD_COMMIT)

On every 30-second metric cycle, the `METRIC_RECORD_COMMIT` event fires once per VLAN. The trigger checks: is this `extrahop.vlan.net`? Does it have non-zero packets? Is this VLAN in the active list or the critical list? Is it already in the "seen" set? If all pass, the VLAN ID is appended to the seen string.

The "seen" set is reset to empty (`||`) at the end of each TIMER_30SEC cycle.

### Phase 3: Comparison and Detection (TIMER_30SEC)

At the start of each 30-second window, the trigger compares active VLANs against the "seen" set. For each VLAN, it resolves the tier and applies the tier-specific threshold and refire interval, then takes one of three actions:

- **Seen and was down past threshold:** Fire a recovery detection with total downtime, then clear the counter.
- **Seen and was counting but below threshold:** Clear the counter, log "back before threshold."
- **Not seen:** Increment the down counter. If the counter reaches the tier's threshold, commit a detection.

---

## Recovery detection

When a VLAN that was past its threshold returns, the trigger fires a recovery `commitDetection` with the same `identityKey`. This consolidates into the existing detection card. The description is updated to show recovery and total downtime. The title doesn't change. Counters are cleared without firing if recovery happens before the threshold.

---

## Cold start behavior

On first enable or restart, a warm-up guard skips the first comparison cycle so VLANs aren't flagged as "down" before any traffic has been observed. Zero false detections on startup.

---

## Detection format

| Field | Value |
|-------|-------|
| Type | `VLAN_Down_Detector` |
| Title | `Data Feed VLAN Lost` |
| Description | Markdown: VLAN ID, tier, duration, sensor hostname, cycle count, TTL note |
| Identity Key | `vlan_down_{VLAN_ID}` (per-VLAN deduplication) |
| Identity TTL | `day` (consolidates within 24 hours) |
| Participants | Empty array |
| Risk Score | Omitted in performance mode; graduated 50-99 in security mode |

The detection description includes a note explaining it will auto-resolve approximately 24 hours after the last update. On recovery, the description is updated to show the VLAN has recovered and the total downtime.

---

## Session table keys

| Key | Value | Expiry | Purpose |
|-----|-------|--------|---------|
| `vlan_det_active` | Pipe-delimited active VLAN IDs | 600s | Survives one missed discovery cycle |
| `vlan_det_seen` | Pipe-delimited seen VLAN IDs | 60s | Resets every 30s; 60s buffer for slow MRC |
| `vlan_det_down_{ID}` | Integer counter | 86400s | Matches identityTtl; never silently expires |
| `vlan_det_init` | 1 | 86400s | Cold start guard |
| `vlan_det_disc` | Integer (0 to DISC_CYCLES-1) | 600s | Discovery throttle |
| `vlan_det_swarn` | 1 | 86400s | One-shot empty config warning |

The trigger uses `Session.replace` rather than `Session.increment` so each access refreshes the expiry timer. This prevents the down counter from silently expiring during long outages.

---

## Performance design

The MRC handler (which fires per VLAN per 30-second cycle) uses pipe-delimited strings with `indexOf()` rather than parsed objects. Zero `JSON.parse`/`JSON.stringify` on the hot path. Tier lookup sets are pre-computed as `Set` objects for O(1) membership checks. JSON parsing only happens in the `REMOTE_RESPONSE` handler (at most once per 5 minutes).

---

## Configuration reference

All parameters live in the `USER CONFIGURATION` block at the top of the script.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DETECTION_CATEGORY` | `'performance'` | `'performance'` for no risk score (data feed monitoring). `'security'` adds graduated risk scoring and uses a separate detection type for SOC pipeline routing. |
| `DYNAMIC_VLAN` | `true` | Auto-discover active VLANs via REST API. |
| `API_ODS_TARGET` | `'EDA'` | HTTP Open Data Stream target name. |
| `ACTIVE_DAYS_REQUIRED` | `7` | Days of continuous hourly traffic to qualify as active. |
| `DISCOVERY_INTERVAL` | `300` | Seconds between API discovery runs. |
| `CRITICAL_VLAN_IDS` | `[]` | VLANs that bypass discovery and are always monitored. |
| `LOW_VALUE_VLAN_IDS` | `[]` | VLANs with intermittent traffic patterns. |
| `VLAN_EXCLUDE_IDS` | `[]` | VLANs to suppress (overrides any tier). |
| `CRITICAL_THRESHOLD` | `10` | Cycles before alerting for critical VLANs (5 min). |
| `STANDARD_THRESHOLD` | `120` | Cycles before alerting for standard VLANs (1 hour). |
| `LOW_VALUE_THRESHOLD` | `360` | Cycles before alerting for low-value VLANs (3 hours). |
| `CRITICAL_REFIRE` | `60` | Cycles between updates for critical (30 min). |
| `STANDARD_REFIRE` | `120` | Cycles between updates for standard (1 hour). |
| `LOW_VALUE_REFIRE` | `360` | Cycles between updates for low-value (3 hours). |
| `STATIC_VLAN_IDS` | `[]` | Manual VLAN list when `DYNAMIC_VLAN` is `false`. |
| `LOG_ENABLED` | `true` | Master switch for all logging. |
| `LOG_LEVEL` | `'INFO'` | `DEBUG` / `INFO` / `WARNING` hierarchical. |
| `EMIT_ACTIVE_VLAN_METRIC` | `false` | Emit snapshot metric with active VLAN count. |

---

## Required trigger configuration

These must be set in the ExtraHop UI, not in the script.

| Setting | Value | Why |
|---------|-------|-----|
| Metric cycle | `30sec` | Matches TIMER_30SEC comparison cycle |
| Metric types | `extrahop.vlan.net` | Platform-level filtering before trigger executes |

---

## Log format

```
5.1.0 <hostname> [LEVEL] <message>
```

Examples:
```
5.1.0 eda01 [INFO] First cycle - warming up
5.1.0 eda01 [INFO] Active VLANs: 23
5.1.0 eda01 [WARNING] VLAN 300 (standard) missing 15/120
5.1.0 eda01 [WARNING] VLAN 300 (standard) down 120 cycles - fired
5.1.0 eda01 [WARNING] VLAN 300 (standard) recovered after 180 cycles
5.1.0 eda01 [INFO] VLAN 200 (critical) back before threshold
```

Messages truncated at 1900 characters (ExtraHop 2048-byte log limit).

---

## Known limitations

1. **Metric zero-value gap.** ExtraHop silently discards zero metric values. If `EMIT_ACTIVE_VLAN_METRIC` is enabled and all active VLANs disappear, the metric stops appearing rather than showing zero.

2. **Top-level metric only.** The active VLAN count is a snapshot, not per-VLAN. Per-VLAN tracking would require `metricAddDetailSnap` (~10 lines to add).

3. **Empty participants.** The API only supports Flow-based participants, which aren't available on TIMER_30SEC. The detection renders correctly without them.

4. **Detection auto-resolve.** There is no API to programmatically close a detection. Detections stay "ongoing" until `identityTtl` expires without a new consolidation. The recovery description makes it clear the VLAN is back, and both outage and recovery descriptions include a TTL note.

---

## Roadmap

### v5.2.0 (planned)

Three additions, all focused on dashboard integration, detection workflow clarity, and routing. No changes to core detection logic.

**Detection title rename.** The current title "Data Feed VLAN Lost" reads as a security incident to anyone outside the tool admin circle. The word "lost" implies attack or compromise. Renaming to "Data Feed VLAN Event" keeps the title neutral and accurate for both outage and recovery states (the same title fires for both, since it's one consolidated detection). Description text continues to specify whether the VLAN is down or recovered.

**Custom metrics for dashboards.** A set of `Network.metricAdd*` calls emitted from existing event handlers. No new event handlers, no impact to the MRC hot path. Lets customers build comprehensive ExtraHop dashboards that track active, recovered, and never-recovered VLANs over time, then alert on metric thresholds without relying on detection descriptions for the big picture.

Planned metrics:

| Metric | Type | Purpose |
|--------|------|---------|
| `vlan_det.active_count` | snapshot | Count of currently monitored VLANs |
| `vlan_det.down_count` | snapshot | Total VLANs currently below their tier threshold |
| `vlan_det.down_critical_count` | snapshot | Critical VLANs currently down |
| `vlan_det.down_standard_count` | snapshot | Standard VLANs currently down |
| `vlan_det.down_low_value_count` | snapshot | Low-value VLANs currently down |
| `vlan_det.outage_total` | count | Cumulative outage detection events |
| `vlan_det.recovery_total` | count | Cumulative recovery events |
| `vlan_det.outages.by_vlan` | detail count | Per-VLAN outage count for flapping detection |
| `vlan_det.downtime.by_vlan` | detail dataset | Per-VLAN downtime distribution (min/p25/p50/p75/max) |

The `outage_total` minus `recovery_total` differential identifies VLANs that went down and never recovered, supporting a "stale outages" dashboard panel without requiring per-VLAN state tracking on the dashboard side.

Detail metric naming follows ExtraHop's documented convention: `<metric_name>.by_<key>`. Per-VLAN metrics use the VLAN ID as the detail key.

Snapshot and dataset types handle the zero-value gap natively. Snapshots are only emitted when the count is positive; dashboards render absence as zero. Dataset metrics give p50/p95/max statistics per VLAN, supporting heatmap visualizations of worst-affected VLANs.

Deployment requires creating Metric Catalog entries for each metric before building the dashboard. This is a one-time configuration in `System Settings > Metric Catalog`.

**Detection categories.** The `commitDetection` options will include a `categories` array. `'performance'` mode uses `['perf.network']`. `'security'` mode uses `['sec']`. This routes detections into the correct buckets in the Reveal(x) UI and improves filterability without changing existing behavior.

### Beyond v5.2.0

Items considered and deferred. These solve real problems but either require customer-driven scope clarification or duplicate platform-native capabilities.

- **Risk score scaling per tier.** Critical VLAN outages would ramp to max risk score faster than low-value outages. Only relevant when `DETECTION_CATEGORY = 'security'`. Limited audience until more customers adopt security mode.
- **Detection batching for burst events.** When a switch fails and many VLANs drop simultaneously, consolidating into a single "multi-VLAN outage" detection would reduce alert fatigue. Requires customer input on burst threshold and consolidation format.
- **Configurable detection title and description templates.** Lets customers match their own ticketing format. Speculative until a customer requests it.
| 5.1.0 | Renamed `LICENSE_MODEL` to `DETECTION_CATEGORY` ('performance'/'security'). Detection name suffix `_NDR` -> `_Security`. Removed title suffix. Code consolidation: 3 tier functions -> 1 (`resolveTier`). 2 fire functions -> 1 with `recovered` flag. Removed unused `STANDARD_VLAN_IDS`. Simplified `logMsg` signature. Hardening: try/catch on `sessionSet`, `Number()` coercion in `resolveTier`. 22% line reduction (592 -> 478). |

---

## License

BSD 2-Clause License. See [LICENSE](../LICENSE).
