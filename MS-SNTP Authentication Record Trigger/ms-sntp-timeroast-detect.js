// ============================================================================================================================
//  MS-SNTP Authentication Record Trigger
//  Version 4.0
//
//  Author:     Matthew Walrath
//  Copyright:  (c) 2026, Matthew Walrath
//  License:    BSD 2-Clause (see LICENSE)
// ============================================================================================================================
//
//  Extracts MS-SNTP authentication trailers from NTP client requests to Domain Controllers and commits
//  enriched records for downstream analysis. ExtraHop does not natively parse MS-SNTP auth trailers or
//  expose the Key ID (AD RID) and MAC fields. This trigger fills that gap.
//
//  Designed for timeroasting detection. Timeroasting is a credential-theft technique (Secura, 2023)
//  that sends crafted NTPv3 requests to Windows DCs, enumerating AD computer account RIDs in the
//  Key ID field. The DC responds with an MD5 MAC derived from each account's NTLM hash, giving the
//  attacker material for offline cracking. No authentication required. No Windows event logs produced.
//
//  Reference: https://github.com/SecuraBV/Timeroast
//  MITRE ATT&CK: Credential Access (T1558, T1003)
//
//
//  HOW IT WORKS
//  ------------
//  Two events for full coverage:
//
//    NTP_MESSAGE   Fires when ExtraHop classifies the flow as NTP. Uses the built-in NTP class,
//                  extracts the auth trailer from NTP.payload, enriches NTP.record, commits via
//                  NTP.commitRecord().
//
//    UDP_PAYLOAD   Fires for unclassified UDP port 123 traffic. Parses the raw payload manually
//                  and commits a custom record via commitRecord(). Catches unanswered single-packet
//                  UDP flows that ExtraHop may never classify.
//
//  Both handlers use Flow.sender / Flow.receiver (not Flow.client / Flow.server). Unanswered UDP
//  flows may never establish the client/server relationship. sender/receiver is always available.
//
//  Early exit filters (before any payload parsing):
//    1. NTP mode 3 (client request only)
//    2. NTP version 3 (MS-SNTP is NTPv3; no NTPv4 extension field walking needed)
//    3. Payload >= 56 bytes (48 header + 4 Key ID + at least 4 MAC bytes)
//
//  Standard MS-SNTP uses a 16-byte MD5 MAC (68-byte packet). The relaxed length check catches
//  SHA1 variants (72 bytes) and non-standard MAC lengths from modified tools.
//
//
//  SETUP
//  -----
//  1. Create the trigger with events: NTP_MESSAGE, UDP_PAYLOAD
//  2. UDP_PAYLOAD advanced options:
//       - Run trigger on all UDP packets: ENABLED
//       - Server Port Range: 123 - 123
//  3. Assign to Domain Controllers (or a device group containing them).
//  4. Set DEBUG_MODE = true. Verify debug log shows parsed packets.
//  5. Set DEBUG_MODE = false, COMMIT_NTP_RECORDS = true for production.
//
//
//  RECORD SCHEMA
//  -------------
//  Auto-populated by ExtraHop:
//    _time, clientAddr, serverAddr
//
//  Added by this trigger:
//    authPresent          boolean    Auth trailer found
//    authKeyId            number     AD RID (little-endian uint32 from Key ID field)
//    authKeyIdHex         string     Key ID as zero-padded 8-char hex
//    authMacHex           string     MAC bytes as hex
//    authMacLen           number     MAC length in bytes (16 = MD5, 20 = SHA1)
//    authAlgGuess         string     'MD5', 'SHA1', or 'unknown(N)'
//    isTimeroastCandidate boolean    True when authKeyId >= RID_FLOOR (500)
//    timeroastReason      string     Classification reason
//    triggerVersion       string     Trigger version
//    triggerEvent         string     'NTP_MESSAGE' or 'UDP_PAYLOAD'
//
// ============================================================================================================================


// ============================================================================================================================
//  1. CONFIGURATION
// ============================================================================================================================

var VERSION = '4.0';

// Set true to log parsed packets without committing records. Set false for production.
var DEBUG_MODE = true;

// Set true to write records to the recordstore.
var COMMIT_NTP_RECORDS = false;

// When true, only commit records where auth extraction succeeds.
var ONLY_COMMIT_IF_AUTH = false;

// AD RIDs >= this value are user/computer accounts. Below 500 = built-in accounts.
var RID_FLOOR = 500;

// --- Internal Constants ---
var NTP_HEADER_LEN   = 48;
var MIN_AUTH_PKT_LEN = 56;   // 48 header + 4 Key ID + 4 minimum MAC bytes
var RECORD_TYPE      = 'ms_sntp';


// ============================================================================================================================
//  2. HELPER FUNCTIONS
//     Defined before the event router per ExtraHop trigger best practices.
// ============================================================================================================================

// --- Auth Parser ---

/*
 * Extract Key ID and MAC from an NTPv3 authentication trailer.
 *
 * MS-SNTP layout: [48 NTP header] [4 Key ID (LE uint32)] [16 MD5 MAC]
 * Also handles non-standard MAC lengths by reading everything after the Key ID.
 *
 * Returns null on failure.
 * Returns { keyId, keyIdHex, macHex, macLength, algGuess } on success.
 */
function extractMsSntpAuth(buffer) {
    var keyId = 0;
    try {
        keyId = Number(buffer.unpack('<I', NTP_HEADER_LEN)[0]);
    } catch (e) {
        return null;
    }

    var macBuffer;
    try {
        macBuffer = buffer.slice(NTP_HEADER_LEN + 4);
    } catch (e) {
        return null;
    }

    var macLen   = macBuffer.length;
    var algGuess = (macLen === 16) ? 'MD5' : (macLen === 20) ? 'SHA1' : 'unknown(' + macLen + ')';

    return {
        keyId:     keyId,
        keyIdHex:  ('00000000' + keyId.toString(16)).slice(-8),
        macHex:    macBuffer.toString('hex'),
        macLength: macLen,
        algGuess:  algGuess
    };
}


// --- Classification ---

/*
 * Classify based on Key ID value.
 * RIDs >= 500 are AD user/computer accounts. Below 500 = built-in.
 */
function classify(authData) {
    if (authData && authData.keyId >= RID_FLOOR) {
        return {
            isCandidate: true,
            reason: 'Auth Key ID ' + authData.keyId + ' (RID >= ' + RID_FLOOR + ')'
        };
    }
    return { isCandidate: false, reason: '' };
}


// --- Record Enrichment (NTP_MESSAGE path) ---

function enrichNtpRecord(authData, result) {
    NTP.record.authPresent          = (authData !== null);
    NTP.record.triggerVersion       = VERSION;
    NTP.record.triggerEvent         = 'NTP_MESSAGE';
    NTP.record.isTimeroastCandidate = result.isCandidate;
    NTP.record.timeroastReason      = result.reason;

    if (authData) {
        NTP.record.authKeyId    = authData.keyId;
        NTP.record.authKeyIdHex = authData.keyIdHex;
        NTP.record.authMacHex   = authData.macHex;
        NTP.record.authMacLen   = authData.macLength;
        NTP.record.authAlgGuess = authData.algGuess;
    }
}


// --- Record Builder (UDP_PAYLOAD path) ---

function buildUpaRecord(buffer, auth, stratum, result) {
    var record = {
        modeName:            'client',
        version:             3,
        stratum:             stratum,
        authPresent:         (auth !== null),
        triggerVersion:      VERSION,
        triggerEvent:        'UDP_PAYLOAD',
        l7proto:             Flow.l7proto,
        packetLength:        buffer.length,
        isTimeroastCandidate: result.isCandidate,
        timeroastReason:      result.reason
    };

    if (auth) {
        record.authKeyId    = auth.keyId;
        record.authKeyIdHex = auth.keyIdHex;
        record.authMacHex   = auth.macHex;
        record.authMacLen   = auth.macLength;
        record.authAlgGuess = auth.algGuess;
    }

    return record;
}


// --- Debug Logging ---

function logPacket(tag, info) {
    var msg = VERSION + ' ' + tag + ' NTPv3 mode 3'
        + ' | ' + info.srcIP + ':' + info.srcPort + ' -> ' + info.dstIP + ':' + info.dstPort
        + ' | pktLen=' + info.pktLen;

    if (info.authData) {
        var a = info.authData;
        msg += ' | keyId=' + a.keyId + ' (0x' + a.keyIdHex + ')'
            + ' macLen=' + a.macLength + ' alg=' + a.algGuess
            + ' | timeroast=' + info.isCandidate;
    } else {
        msg += ' | authExtractFailed';
    }

    debug(msg);
}


// ============================================================================================================================
//  3. EVENT ROUTER
// ============================================================================================================================

if (event === 'NTP_MESSAGE') {
    handleNtpMessage();
} else if (event === 'UDP_PAYLOAD') {
    handleUdpPayload();
}


// ============================================================================================================================
//  4. NTP_MESSAGE HANDLER
// ============================================================================================================================

function handleNtpMessage() {
    if (NTP.mode !== 3 || NTP.version !== 3) {
        return;
    }

    var payload = NTP.payload;
    if (!payload || payload.length < MIN_AUTH_PKT_LEN) {
        return;
    }

    var authData = extractMsSntpAuth(payload);
    var srcIP    = Flow.sender.ipaddr;
    var dstIP    = Flow.receiver.ipaddr;
    var result   = classify(authData);

    if (DEBUG_MODE) {
        logPacket('[NTP_MESSAGE]', {
            srcIP: srcIP, srcPort: Flow.sender.port,
            dstIP: dstIP, dstPort: Flow.receiver.port,
            pktLen: payload.length,
            authData: authData, isCandidate: result.isCandidate
        });
    }

    var shouldCommit = COMMIT_NTP_RECORDS && (!ONLY_COMMIT_IF_AUTH || authData);
    if (shouldCommit) {
        enrichNtpRecord(authData, result);
        if (!DEBUG_MODE) {
            NTP.commitRecord();
        }
    }
}


// ============================================================================================================================
//  5. UDP_PAYLOAD HANDLER
// ============================================================================================================================

function handleUdpPayload() {
    if (Flow.l7proto !== 'udp:123' && Flow.receiver.port !== 123) {
        return;
    }

    var buf = Flow.sender.payload;
    if (!buf || buf.length < MIN_AUTH_PKT_LEN) {
        return;
    }

    var flagsByte = 0;
    try {
        flagsByte = Number(buf.unpack('B')[0]);
    } catch (e) {
        return;
    }

    var mode       = flagsByte & 0x7;
    var ntpVersion = (flagsByte >> 3) & 0x7;

    if (mode !== 3 || ntpVersion !== 3) {
        return;
    }

    var authData = extractMsSntpAuth(buf);
    var srcIP    = Flow.sender.ipaddr;
    var dstIP    = Flow.receiver.ipaddr;
    var result   = classify(authData);

    if (DEBUG_MODE) {
        logPacket('[UDP_PAYLOAD]', {
            srcIP: srcIP, srcPort: Flow.sender.port,
            dstIP: dstIP, dstPort: Flow.receiver.port,
            pktLen: buf.length,
            authData: authData, isCandidate: result.isCandidate
        });
    }

    var shouldCommit = COMMIT_NTP_RECORDS && (!ONLY_COMMIT_IF_AUTH || authData);
    if (shouldCommit) {
        var stratum = -1;
        try { stratum = Number(buf.unpack('xB')[0]); } catch (e) { /* default */ }

        var record = buildUpaRecord(buf, authData, stratum, result);
        if (!DEBUG_MODE) {
            commitRecord(RECORD_TYPE, record);
        }
    }
}
