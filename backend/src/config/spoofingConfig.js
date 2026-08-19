"use strict";

const DEFAULT_NEIGHBOR_LOOKUP_TIMEOUT_MS = 1000;

function parseBoolean(value, defaultValue = false) {
    if (value === undefined || value === null || value === "") {
        return defaultValue;
    }

    const normalized = String(value).trim().toLowerCase();

    if (["true", "1", "yes", "on"].includes(normalized)) {
        return true;
    }

    if (["false", "0", "no", "off"].includes(normalized)) {
        return false;
    }

    return defaultValue;
}

function parseTimeoutMs(value) {
    if (value === undefined || value === null || value === "") {
        return DEFAULT_NEIGHBOR_LOOKUP_TIMEOUT_MS;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < 100 ||
        parsed > 5000
    ) {
        return DEFAULT_NEIGHBOR_LOOKUP_TIMEOUT_MS;
    }

    return parsed;
}

const allowSimulatedNetworkContextConfigured = parseBoolean(
    process.env.ALLOW_SIMULATED_NETWORK_CONTEXT,
    false
);

const runningInProduction = process.env.NODE_ENV === "production";

module.exports = {
    allowSimulatedNetworkContext:
        allowSimulatedNetworkContextConfigured && !runningInProduction,
    allowSimulatedNetworkContextConfigured,
    denyIncompleteNetworkContext: parseBoolean(
        process.env.DENY_INCOMPLETE_NETWORK_CONTEXT,
        false
    ),
    neighborLookupTimeoutMs: parseTimeoutMs(
        process.env.NEIGHBOR_LOOKUP_TIMEOUT_MS
    )
};
