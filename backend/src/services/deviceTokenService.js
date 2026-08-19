"use strict";

const crypto = require("node:crypto");

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 3600;

let developmentSecret = null;

function parseTtlSeconds(value) {
    if (value === undefined || value === null || value === "") {
        return DEFAULT_TTL_SECONDS;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < MIN_TTL_SECONDS ||
        parsed > MAX_TTL_SECONDS
    ) {
        return DEFAULT_TTL_SECONDS;
    }

    return parsed;
}

function getTokenSecret() {
    const configured = process.env.DEVICE_ACCESS_TOKEN_SECRET;

    if (
        typeof configured === "string" &&
        configured.trim().length >= 32
    ) {
        return configured.trim();
    }

    if (process.env.NODE_ENV === "production") {
        throw new Error(
            "DEVICE_ACCESS_TOKEN_SECRET must be configured with at least 32 characters"
        );
    }

    if (!developmentSecret) {
        developmentSecret = crypto.randomBytes(32).toString("hex");
        console.warn(
            "DEVICE_ACCESS_TOKEN_SECRET is not configured. " +
            "Using an ephemeral development-only device token secret."
        );
    }

    return developmentSecret;
}

function base64UrlJson(value) {
    return Buffer
        .from(JSON.stringify(value))
        .toString("base64url");
}

function signToken(unsignedToken) {
    return crypto
        .createHmac("sha256", getTokenSecret())
        .update(unsignedToken)
        .digest("base64url");
}

function issueDeviceAccessToken({ did, authEventId }) {
    const ttlSeconds = parseTtlSeconds(
        process.env.DEVICE_ACCESS_TOKEN_TTL_SECONDS
    );
    const issuedAtSeconds = Math.floor(Date.now() / 1000);
    const expiresAtSeconds = issuedAtSeconds + ttlSeconds;
    const header = {
        alg: "HS256",
        typ: "JWT"
    };
    const payload = {
        sub: did,
        authEventId,
        iat: issuedAtSeconds,
        exp: expiresAtSeconds
    };
    const unsignedToken =
        `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
    const signature = signToken(unsignedToken);

    return {
        token: `${unsignedToken}.${signature}`,
        tokenType: "Bearer",
        expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
        expiresInSeconds: ttlSeconds
    };
}

module.exports = {
    issueDeviceAccessToken
};
