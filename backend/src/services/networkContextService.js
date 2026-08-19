"use strict";

const { execFile } = require("node:child_process");
const net = require("node:net");
const { promisify } = require("node:util");

const spoofingConfig = require("../config/spoofingConfig");

const execFileAsync = promisify(execFile);

function normalizeIpAddress(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return null;
    }

    let normalized = value.trim();

    if (normalized.startsWith("::ffff:")) {
        normalized = normalized.slice("::ffff:".length);
    }

    if (normalized === "::1") {
        return "127.0.0.1";
    }

    if (net.isIP(normalized) === 0) {
        return null;
    }

    return normalized;
}

function normalizeMacAddress(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return null;
    }

    const compact = value
        .trim()
        .replace(/[-:.]/g, "")
        .toUpperCase();

    if (!/^[0-9A-F]{12}$/.test(compact)) {
        return null;
    }

    return compact.match(/.{2}/g).join(":");
}

function getHeaderValue(req, name) {
    const value = req.get(name);

    if (Array.isArray(value)) {
        return value[0];
    }

    return value;
}

function getSocketIpAddress(req) {
    return normalizeIpAddress(
        req.socket?.remoteAddress ||
        req.connection?.remoteAddress ||
        ""
    );
}

async function resolveNeighborMacAddress(ipAddress) {
    const normalizedIp = normalizeIpAddress(ipAddress);

    if (!normalizedIp || normalizedIp === "127.0.0.1") {
        return null;
    }

    try {
        const { stdout } = await execFileAsync(
            "ip",
            ["neigh", "show", normalizedIp],
            {
                timeout: spoofingConfig.neighborLookupTimeoutMs,
                maxBuffer: 4096
            }
        );

        const match = stdout.match(
            /\blladdr\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b/
        );

        return match ? normalizeMacAddress(match[1]) : null;
    } catch {
        return null;
    }
}

function getSimulatedNetworkContext(req) {
    const simulatedIp = getHeaderValue(req, "X-Simulated-Source-IP");
    const simulatedMac = getHeaderValue(req, "X-Simulated-Source-MAC");

    if (!simulatedIp && !simulatedMac) {
        return null;
    }

    if (!spoofingConfig.allowSimulatedNetworkContext) {
        return null;
    }

    const normalizedIp = simulatedIp
        ? normalizeIpAddress(simulatedIp)
        : null;
    const normalizedMac = simulatedMac
        ? normalizeMacAddress(simulatedMac)
        : null;

    if (simulatedIp && !normalizedIp) {
        const error = new Error("Simulated source IP is invalid");
        error.statusCode = 400;
        throw error;
    }

    if (simulatedMac && !normalizedMac) {
        const error = new Error("Simulated source MAC is invalid");
        error.statusCode = 400;
        throw error;
    }

    console.warn(
        "Using simulated network context for authentication request",
        {
            simulatedIpAddress: normalizedIp,
            simulatedMacAddress: normalizedMac
        }
    );

    return {
        observedIpAddress: normalizedIp,
        observedMacAddress: normalizedMac,
        ipSource: normalizedIp ? "simulated-header" : "unavailable",
        macSource: normalizedMac ? "simulated-header" : "unavailable",
        simulationUsed: true
    };
}

async function getObservedNetworkContext(req) {
    const simulatedContext = getSimulatedNetworkContext(req);

    if (simulatedContext) {
        return simulatedContext;
    }

    const observedIpAddress = getSocketIpAddress(req);
    const observedMacAddress =
        await resolveNeighborMacAddress(observedIpAddress);

    return {
        observedIpAddress,
        observedMacAddress,
        ipSource: observedIpAddress ? "socket" : "unavailable",
        macSource: observedMacAddress ? "neighbor-table" : "unavailable",
        simulationUsed: false
    };
}

module.exports = {
    getObservedNetworkContext,
    normalizeIpAddress,
    normalizeMacAddress
};
