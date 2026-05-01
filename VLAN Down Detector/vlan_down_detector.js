/*
###############################################################################################################################
  Trigger:      VLAN Down Detector
  Version:      5.1.0
  Author:       Mike Saur (ExtraHop Networks)
  Contributor:  Matthew Walrath (ExtraHop Networks)
  Events:       TIMER_30SEC, REMOTE_RESPONSE, METRIC_RECORD_COMMIT
  Assignment:   Global events only

  Detects when active VLANs stop transmitting packets. Three monitoring tiers
  (critical, standard, low_value) with independent thresholds and refire rates.
  Discovers active VLANs via REST API, observes traffic via MRC, compares every
  30 seconds. Commits a detection when a VLAN is missing for its tier threshold.
  Fires a recovery update when the VLAN returns.

  Advanced Trigger Options (MUST be configured in the UI):
    Metric cycle: 30sec
    Metric types: extrahop.vlan.net
###############################################################################################################################
*/

// ============================================================================================================================
//  USER CONFIGURATION                                                                                                       //
// ============================================================================================================================

// Determines whether this fires as a performance or security detection.
// 'performance' = no risk score (typical for data-feed monitoring).
// 'security'    = adds graduated risk score (50-99 over ~60 minutes)
//                 and uses a separate detection type so it can be routed
//                 to the SOC pipeline. Requires NDR license to be useful.
/** @type {'performance' | 'security'} */
const DETECTION_CATEGORY   = 'performance'
const DYNAMIC_VLAN         = true
const API_ODS_TARGET       = 'EDA'
const ACTIVE_DAYS_REQUIRED = 7
const DISCOVERY_INTERVAL   = 300

// Tier arrays. Critical VLANs bypass discovery and are always monitored.
// Discovered VLANs default to standard. VLAN_EXCLUDE_IDS suppresses any tier.
const CRITICAL_VLAN_IDS    = []
const LOW_VALUE_VLAN_IDS   = []
const VLAN_EXCLUDE_IDS     = []

// Per-tier thresholds (consecutive 30s cycles before detection)
const CRITICAL_THRESHOLD   = 10     // 5 minutes
const STANDARD_THRESHOLD   = 120    // 1 hour
const LOW_VALUE_THRESHOLD  = 360    // 3 hours

// Per-tier refire intervals (cycles between detection updates)
const CRITICAL_REFIRE      = 60     // every 30 minutes
const STANDARD_REFIRE      = 120    // every 1 hour
const LOW_VALUE_REFIRE     = 360    // every 3 hours

// Static VLAN list. Only used when DYNAMIC_VLAN is false.
const STATIC_VLAN_IDS      = []

const LOG_ENABLED          = true
const LOG_LEVEL            = 'INFO'
const EMIT_ACTIVE_VLAN_METRIC = false

// ============================================================================================================================
//  CONSTANTS                                                                                                                //
// ============================================================================================================================

const VERSION  = '5.1.0'
const HOSTNAME = System.hostname || 'unknown'

const SK_ACTIVE  = 'vlan_det_active'
const SK_SEEN    = 'vlan_det_seen'
const SK_DOWN    = 'vlan_det_down_'
const SK_INIT    = 'vlan_det_init'
const SK_DISC    = 'vlan_det_disc'
const SK_WARNED  = 'vlan_det_swarn'

const EXP_ACTIVE = 600
const EXP_SEEN   = 60
const EXP_DOWN   = 86400
const EXP_INIT   = 86400

const LEVEL_RANK = { DEBUG: 0, INFO: 1, WARNING: 2 }
const CFG_RANK   = LEVEL_RANK[LOG_LEVEL] || 1

const DISC_CYCLES = Math.max(1, Math.round(DISCOVERY_INTERVAL / 30))

const RISK_MIN   = 50
const RISK_MAX   = 99
const RISK_RAMP  = 120
const LOG_MAX    = 1900

// Pre-computed tier lookup sets
const TIER_CRIT = new Set(CRITICAL_VLAN_IDS)
const TIER_LOW  = new Set(LOW_VALUE_VLAN_IDS)

// ============================================================================================================================
//  FUNCTIONS                                                                                                                //
// ============================================================================================================================

function pipeHas(str, id) {
    return str.indexOf('|' + id + '|') !== -1
}

function pipeToArray(str) {
    if (!str || str === '||') return []
    const parts = str.substring(1, str.length - 1).split('|')
    const arr = []
    for (let i = 0; i < parts.length; i++) {
        const n = parseInt(parts[i], 10)
        if (!isNaN(n)) arr.push(n)
    }
    return arr
}

function arrayToPipe(arr) {
    if (arr.length === 0) return '||'
    return '|' + arr.join('|') + '|'
}

function logMsg(text, level) {
    if (!LOG_ENABLED) return
    const rank = LEVEL_RANK[level] || 1
    if (rank < CFG_RANK) return
    let msg = VERSION + ' ' + HOSTNAME + ' [' + level + '] ' + text
    if (msg.length > LOG_MAX) {
        msg = msg.substring(0, LOG_MAX) + '...(truncated)'
    }
    log(msg)
}

function sessionSet(key, value, expire) {
    try {
        Session.replace(key, value, {
            expire: expire,
            priority: Session.PRIORITY_HIGH
        })
    } catch (e) {
        logMsg('Session write failed for ' + key + ': '
            + e.message, 'WARNING')
    }
}

// Returns { tier, threshold, refire } in a single lookup pass.
// Coerces vlan to Number for safe Set.has() comparison since
// Set uses === (strict equality) for membership.
function resolveTier(vlan) {
    const id = Number(vlan)
    if (TIER_CRIT.has(id)) {
        return {
            tier: 'critical',
            threshold: CRITICAL_THRESHOLD,
            refire: CRITICAL_REFIRE
        }
    }
    if (TIER_LOW.has(id)) {
        return {
            tier: 'low_value',
            threshold: LOW_VALUE_THRESHOLD,
            refire: LOW_VALUE_REFIRE
        }
    }
    return {
        tier: 'standard',
        threshold: STANDARD_THRESHOLD,
        refire: STANDARD_REFIRE
    }
}

function formatDuration(secs) {
    if (secs < 60) return secs + ' seconds'
    const h = Math.floor(secs / 3600)
    const m = Math.floor((secs % 3600) / 60)
    const s = secs % 60
    const hl = h === 1 ? 'hour' : 'hours'
    const ml = m === 1 ? 'minute' : 'minutes'
    const sl = s === 1 ? 'second' : 'seconds'
    if (h === 0) {
        if (s === 0) return m + ' ' + ml
        return m + ' ' + ml + ' ' + s + ' ' + sl
    }
    if (m === 0) return h + ' ' + hl
    return h + ' ' + hl + ' ' + m + ' ' + ml
}

function handleGetVlans(body) {
    if (!Array.isArray(body) || body.length === 0) {
        logMsg('No VLANs from API', 'WARNING')
        return
    }
    const exclude = new Set(VLAN_EXCLUDE_IDS)
    const ids = []
    for (let i = 0; i < body.length; i++) {
        const item = body[i]
        if (item && item.id !== undefined && !exclude.has(item.id)) {
            ids.push(item.id)
        }
    }
    if (ids.length === 0) {
        logMsg('No VLAN IDs after exclude filter', 'WARNING')
        return
    }
    try {
        Remote.HTTP(API_ODS_TARGET).post({
            path: '/api/v1/metrics',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json'
            },
            payload: JSON.stringify({
                cycle: '1hr',
                from: '-' + ACTIVE_DAYS_REQUIRED + 'd',
                metric_category: 'net',
                metric_specs: [{ name: 'pkts' }],
                object_ids: ids,
                object_type: 'vlan',
                until: 0
            }),
            context: 'get_metrics',
            enableResponseEvent: true
        })
    } catch (e) {
        logMsg('POST /metrics failed: ' + e.message, 'WARNING')
    }
}

function handleGetMetrics(body) {
    const stats = body.stats
    if (!Array.isArray(stats)) {
        logMsg('Metrics response missing stats', 'WARNING')
        return
    }
    const needed = (ACTIVE_DAYS_REQUIRED * 24) + 1
    const counts = new Map()
    for (let i = 0; i < stats.length; i++) {
        if (!stats[i] || stats[i].oid === undefined) continue
        const v = stats[i].oid
        counts.set(v, (counts.get(v) || 0) + 1)
    }
    const active = []
    counts.forEach(function (c, v) {
        if (c >= needed) active.push(v)
    })

    sessionSet(SK_ACTIVE, arrayToPipe(active), EXP_ACTIVE)
    logMsg('Active VLANs: ' + active.length, 'INFO')

    if (EMIT_ACTIVE_VLAN_METRIC && active.length > 0) {
        try {
            Network.metricAddSnap('vlan_det_active_count', active.length)
        } catch (e) {
            logMsg('Metric emit failed: ' + e.message, 'WARNING')
        }
    }
}

function compareVlans() {
    // Build the monitored VLAN list
    let active
    if (DYNAMIC_VLAN) {
        const str = Session.lookup(SK_ACTIVE)
        active = (str && str !== '||') ? pipeToArray(str) : []
    } else {
        active = STATIC_VLAN_IDS.slice()
    }

    // Merge critical VLANs unconditionally (always monitored)
    const present = new Set(active)
    for (let i = 0; i < CRITICAL_VLAN_IDS.length; i++) {
        if (!present.has(CRITICAL_VLAN_IDS[i])) {
            active.push(CRITICAL_VLAN_IDS[i])
        }
    }

    // Apply exclude filter (overrides any tier)
    if (VLAN_EXCLUDE_IDS.length > 0) {
        const ex = new Set(VLAN_EXCLUDE_IDS)
        active = active.filter(function (v) { return !ex.has(v) })
    }

    if (active.length === 0) {
        logMsg('No active VLANs to monitor', 'DEBUG')
        return
    }

    const seenStr = Session.lookup(SK_SEEN) || '||'

    for (let i = 0; i < active.length; i++) {
        const vlan = active[i]
        const key = SK_DOWN + vlan
        const cfg = resolveTier(vlan)

        if (pipeHas(seenStr, vlan)) {
            // VLAN healthy. Check for recovery.
            const was = Session.lookup(key)
            if (was !== null && typeof was === 'number'
                && was >= cfg.threshold) {
                fireDetection(vlan, was, cfg, true)
                logMsg('VLAN ' + vlan + ' (' + cfg.tier
                    + ') recovered after ' + was + ' cycles', 'WARNING')
            } else if (was !== null) {
                logMsg('VLAN ' + vlan + ' (' + cfg.tier
                    + ') back before threshold', 'INFO')
            }
            if (was !== null) Session.remove(key)
            continue
        }

        // VLAN missing. Increment counter.
        const prev = Session.lookup(key)
        const count = (prev !== null && typeof prev === 'number')
            ? prev + 1 : 1
        sessionSet(key, count, EXP_DOWN)

        if (count < cfg.threshold) {
            logMsg('VLAN ' + vlan + ' (' + cfg.tier + ') missing '
                + count + '/' + cfg.threshold, 'WARNING')
            continue
        }
        const past = count - cfg.threshold
        if (past !== 0 && past % cfg.refire !== 0) continue

        fireDetection(vlan, count, cfg, false)
        logMsg('VLAN ' + vlan + ' (' + cfg.tier + ') down '
            + count + ' cycles - fired', 'WARNING')
    }
}

// Fires a detection. recovered=false for outage, recovered=true for recovery.
// Both share identityKey for consolidation into the same ongoing detection.
function fireDetection(vlan, count, cfg, recovered) {
    const isSecurity = DETECTION_CATEGORY === 'security'
    // Different detection type for security so PNC can route it
    // separately (e.g. SOC pipeline vs performance webhook).
    const name = isSecurity
        ? 'VLAN_Down_Detector_Security'
        : 'VLAN_Down_Detector'
    const title = 'Data Feed VLAN Lost'
    const dur = formatDuration(count * 30)

    let body, note
    if (recovered) {
        body = '**VLAN ' + vlan + '** has recovered.'
        note = 'This detection will expire ~24 hours after this'
            + ' recovery update (identityTtl: day). No further updates'
            + ' will be sent unless the VLAN goes down again.'
    } else {
        body = '**VLAN ' + vlan + '** has stopped receiving or'
            + ' transmitting packets.'
        note = 'This detection auto-resolves ~24 hours after the last'
            + ' update (identityTtl: day).'
    }
    const desc = body + '\n\n'
        + '* **Tier:** ' + cfg.tier + '\n'
        + '* **' + (recovered ? 'Downtime' : 'Duration') + ':** ' + dur + '\n'
        + '* **Sensor:** ' + HOSTNAME + '\n'
        + '* **Down cycles:** ' + count
        + ' (threshold: ' + cfg.threshold + ')\n'
        + '* **Note:** ' + note

    /** @type {'day'} */
    const ttl = 'day'
    const opts = {
        title: title,
        description: desc,
        participants: [],
        identityKey: 'vlan_down_' + vlan,
        identityTtl: ttl
    }
    if (isSecurity && !recovered) {
        const past = Math.max(0, count - cfg.threshold)
        const ramp = Math.min(1, past / RISK_RAMP)
        opts.riskScore = Math.round(
            RISK_MIN + (RISK_MAX - RISK_MIN) * ramp
        )
    }
    try { commitDetection(name, opts) }
    catch (e) {
        logMsg('Detection failed for VLAN ' + vlan + ': '
            + e.message, 'WARNING')
    }
}

// ============================================================================================================================
//  EVENT: TIMER_30SEC                                                                                                       //
// ============================================================================================================================

if (event === 'TIMER_30SEC') {

    if (!DYNAMIC_VLAN
        && STATIC_VLAN_IDS.length === 0
        && CRITICAL_VLAN_IDS.length === 0
        && Session.lookup(SK_WARNED) === null) {
        logMsg('No VLANs configured to monitor', 'WARNING')
        sessionSet(SK_WARNED, 1, EXP_INIT)
    }

    if (DYNAMIC_VLAN) {
        const raw = Session.lookup(SK_DISC)
        const counter = (raw !== null && typeof raw === 'number')
            ? (raw + 1) % DISC_CYCLES : 0
        sessionSet(SK_DISC, counter, EXP_ACTIVE)
        if (counter === 0) {
            try {
                Remote.HTTP(API_ODS_TARGET).get({
                    path: '/api/v1/networks/0/vlans',
                    headers: { Accept: 'application/json' },
                    context: 'get_vlans',
                    enableResponseEvent: true
                })
            } catch (e) {
                logMsg('GET /vlans failed: ' + e.message, 'WARNING')
            }
        }
    }

    if (Session.lookup(SK_INIT) === null) {
        sessionSet(SK_INIT, 1, EXP_INIT)
        logMsg('First cycle - warming up', 'INFO')
    } else {
        compareVlans()
    }

    sessionSet(SK_SEEN, '||', EXP_SEEN)
}

// ============================================================================================================================
//  EVENT: REMOTE_RESPONSE                                                                                                   //
// ============================================================================================================================

if (event === 'REMOTE_RESPONSE') {
    const rsp = Remote.response
    const ctx = rsp.context
    if (rsp.statusCode < 200 || rsp.statusCode >= 300) {
        logMsg(ctx + ' returned ' + rsp.statusCode, 'WARNING')
        return
    }
    let body = null
    try {
        body = rsp.body ? JSON.parse(rsp.body.decode('utf-8')) : null
    } catch (e) {
        logMsg('Parse failed for ' + ctx, 'WARNING')
        return
    }
    if (body === null) {
        logMsg('Empty body from ' + ctx, 'WARNING')
        return
    }
    if (ctx === 'get_vlans') handleGetVlans(body)
    else if (ctx === 'get_metrics') handleGetMetrics(body)
}

// ============================================================================================================================
//  EVENT: METRIC_RECORD_COMMIT                                                                                              //
//  Hot path: fires per VLAN per 30s cycle. Zero JSON.parse/stringify.                                                       //
//  Pipe-delimited strings + indexOf per best practices.                                                                     //
// ============================================================================================================================

if (event === 'METRIC_RECORD_COMMIT') {
    if (MetricRecord.id !== 'extrahop.vlan.net') return

    const pkts = MetricRecord.fields['pkts']
    if (pkts === undefined || pkts === 0) return

    const vlanId = MetricRecord.object['id']

    // Track if VLAN is in active list OR critical list
    const activeStr = Session.lookup(SK_ACTIVE)
    const inActive = activeStr !== null && activeStr !== '||'
        && pipeHas(activeStr, vlanId)
    const inCritical = TIER_CRIT.has(vlanId)
    if (!inActive && !inCritical) return

    const seenStr = Session.lookup(SK_SEEN) || '||'
    if (pipeHas(seenStr, vlanId)) return

    const updated = (seenStr === '||')
        ? '|' + vlanId + '|'
        : seenStr + vlanId + '|'
    sessionSet(SK_SEEN, updated, EXP_SEEN)
}
