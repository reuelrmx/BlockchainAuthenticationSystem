"use strict";

const SCENARIO_NAMES = {
    LEGITIMATE: "LEGITIMATE",
    MAC_SPOOF: "MAC_SPOOF",
    IP_SPOOF: "IP_SPOOF",
    MAC_IP_SPOOF: "MAC_IP_SPOOF",
    INVALID_SIGNATURE: "INVALID_SIGNATURE",
    REPLAY: "REPLAY",
    SUSPENDED: "SUSPENDED",
    REVOKED: "REVOKED"
};

const SPOOFING_SCENARIOS = new Set([
    SCENARIO_NAMES.MAC_SPOOF,
    SCENARIO_NAMES.IP_SPOOF,
    SCENARIO_NAMES.MAC_IP_SPOOF
]);

const LEGITIMATE_SCENARIOS = new Set([
    SCENARIO_NAMES.LEGITIMATE
]);

function replaceLastIpOctet(ipAddress, replacement) {
    const parts = String(ipAddress || "").split(".");

    if (parts.length !== 4) {
        return "192.168.1.99";
    }

    parts[3] = String(replacement);

    return parts.join(".");
}

function buildWrongIpAddress(registeredIpAddress) {
    const preferred = replaceLastIpOctet(registeredIpAddress, 99);

    if (preferred !== registeredIpAddress) {
        return preferred;
    }

    return replaceLastIpOctet(registeredIpAddress, 98);
}

function buildWrongMacAddress(registeredMacAddress) {
    const normalized = String(registeredMacAddress || "")
        .trim()
        .toUpperCase();

    if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(normalized)) {
        return "AA:BB:CC:DD:EE:99";
    }

    const parts = normalized.split(":");
    parts[5] = parts[5] === "99" ? "98" : "99";

    return parts.join(":");
}

function buildScenarios({
    registeredMacAddress,
    registeredIpAddress,
    includeSuspended = true,
    includeRevoked = true
}) {
    const wrongMacAddress = buildWrongMacAddress(registeredMacAddress);
    const wrongIpAddress = buildWrongIpAddress(registeredIpAddress);

    const scenarios = [
        {
            name: SCENARIO_NAMES.LEGITIMATE,
            expectedDecision: "GRANTED",
            expectedSpoofingClassification: "NONE",
            expectedHttpStatus: 200,
            simulatedMacAddress: registeredMacAddress,
            simulatedIpAddress: registeredIpAddress
        },
        {
            name: SCENARIO_NAMES.MAC_SPOOF,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "MAC_MISMATCH",
            expectedHttpStatus: 403,
            simulatedMacAddress: wrongMacAddress,
            simulatedIpAddress: registeredIpAddress
        },
        {
            name: SCENARIO_NAMES.IP_SPOOF,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "IP_MISMATCH",
            expectedHttpStatus: 403,
            simulatedMacAddress: registeredMacAddress,
            simulatedIpAddress: wrongIpAddress
        },
        {
            name: SCENARIO_NAMES.MAC_IP_SPOOF,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "MAC_AND_IP_MISMATCH",
            expectedHttpStatus: 403,
            simulatedMacAddress: wrongMacAddress,
            simulatedIpAddress: wrongIpAddress
        },
        {
            name: SCENARIO_NAMES.INVALID_SIGNATURE,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "NOT_EVALUATED",
            expectedHttpStatus: 401,
            simulatedMacAddress: registeredMacAddress,
            simulatedIpAddress: registeredIpAddress,
            invalidSignature: true
        },
        {
            name: SCENARIO_NAMES.REPLAY,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "NOT_EVALUATED",
            expectedHttpStatus: 401,
            simulatedMacAddress: registeredMacAddress,
            simulatedIpAddress: registeredIpAddress,
            replay: true,
            replayExpectedFirstDecision: "GRANTED",
            replayExpectedFirstSpoofingClassification: "NONE"
        }
    ];

    if (includeSuspended) {
        scenarios.push({
            name: SCENARIO_NAMES.SUSPENDED,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "NOT_EVALUATED",
            expectedHttpStatus: 403,
            statusScenario: "SUSPENDED"
        });
    }

    if (includeRevoked) {
        scenarios.push({
            name: SCENARIO_NAMES.REVOKED,
            expectedDecision: "DENIED",
            expectedSpoofingClassification: "NOT_EVALUATED",
            expectedHttpStatus: 403,
            statusScenario: "REVOKED"
        });
    }

    return scenarios;
}

module.exports = {
    SCENARIO_NAMES,
    SPOOFING_SCENARIOS,
    LEGITIMATE_SCENARIOS,
    buildScenarios
};
