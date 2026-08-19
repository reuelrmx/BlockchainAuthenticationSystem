"use strict";

const { execFile } = require("node:child_process");
const crypto = require("node:crypto");
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

function hashMacAddress(value) {
    const normalized = normalizeMacAddress(value);

    if (!normalized) {
        return null;
    }

    return crypto
        .createHash("sha256")
        .update(normalized)
        .digest("hex");
}

function ipv4ToNumber(ipAddress) {
    const normalizedIpAddress = normalizeIpAddress(ipAddress);

    if (
        !normalizedIpAddress ||
        net.isIP(normalizedIpAddress) !== 4
    ) {
        return null;
    }

    return normalizedIpAddress
        .split(".")
        .reduce((value, section) =>
            ((value << 8) >>> 0) + Number(section),
        0) >>> 0;
}

function normalizeAllowedIpCidr(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return null;
    }

    const trimmed = value.trim();
    const parts = trimmed.split("/");
    const ipAddress = normalizeIpAddress(parts[0]);

    if (!ipAddress || net.isIP(ipAddress) !== 4) {
        return null;
    }

    if (parts.length === 1) {
        return `${ipAddress}/32`;
    }

    if (parts.length !== 2 || !/^\d{1,2}$/.test(parts[1])) {
        return null;
    }

    const prefixLength = Number(parts[1]);

    if (prefixLength < 0 || prefixLength > 32) {
        return null;
    }

    return `${ipAddress}/${prefixLength}`;
}

function isIpInCidr(ipAddress, allowedCidr) {
    const observedIpNumber = ipv4ToNumber(ipAddress);
    const normalizedCidr = normalizeAllowedIpCidr(allowedCidr);

    if (observedIpNumber === null || !normalizedCidr) {
        return null;
    }

    const [networkAddress, prefixLengthText] =
        normalizedCidr.split("/");
    const networkNumber = ipv4ToNumber(networkAddress);
    const prefixLength = Number(prefixLengthText);

    if (networkNumber === null) {
        return null;
    }

    if (prefixLength === 0) {
        return true;
    }

    const mask = (0xffffffff << (32 - prefixLength)) >>> 0;

    return (
        (observedIpNumber & mask) >>> 0
    ) === (
        (networkNumber & mask) >>> 0
    );
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
    hashMacAddress,
    isIpInCidr,
    normalizeAllowedIpCidr,
    normalizeIpAddress,
    normalizeMacAddress
};
