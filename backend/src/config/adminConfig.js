"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

const backendRoot = path.resolve(__dirname, "../..");
const DEFAULT_SESSION_TTL_SECONDS = 3600;
const MAX_SESSION_TTL_SECONDS = 86400;
const DEFAULT_HTTPS_PORT = 3443;
const DEFAULT_DASHBOARD_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:4173",
    "https://localhost:5173",
    "https://localhost:4173"
];

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

function parsePort(value, defaultValue) {
    if (value === undefined || value === null || value === "") {
        return defaultValue;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < 1 ||
        parsed > 65535
    ) {
        return defaultValue;
    }

    return parsed;
}

function parseSessionTtlSeconds(value) {
    if (value === undefined || value === null || value === "") {
        return DEFAULT_SESSION_TTL_SECONDS;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < 60 ||
        parsed > MAX_SESSION_TTL_SECONDS
    ) {
        return DEFAULT_SESSION_TTL_SECONDS;
    }

    return parsed;
}

function parseOrigins(value) {
    if (value === undefined || value === null || value.trim() === "") {
        return DEFAULT_DASHBOARD_ORIGINS;
    }

    return value
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean)
        .filter((origin) => origin !== "*");
}

function parseSameSite(value, defaultValue) {
    if (value === undefined || value === null || value === "") {
        return defaultValue;
    }

    const normalized = String(value).trim().toLowerCase();

    if (normalized === "none") {
        return "None";
    }

    if (normalized === "strict") {
        return "Strict";
    }

    if (normalized === "lax") {
        return "Lax";
    }

    return defaultValue;
}

function resolveFromBackendRoot(value, fallback) {
    const target = value || fallback;

    if (path.isAbsolute(target)) {
        return target;
    }

    return path.resolve(backendRoot, target);
}

function getSessionSecret() {
    const configuredSecret = process.env.ADMIN_SESSION_SECRET;

    if (
        typeof configuredSecret === "string" &&
        configuredSecret.trim().length >= 32
    ) {
        return configuredSecret.trim();
    }

    if (process.env.NODE_ENV === "production") {
        throw new Error(
            "ADMIN_SESSION_SECRET must be configured with at least 32 characters"
        );
    }

    console.warn(
        "ADMIN_SESSION_SECRET is not configured. " +
        "Using an ephemeral development-only admin session secret."
    );

    return crypto.randomBytes(32).toString("hex");
}

const httpsEnabled = parseBoolean(process.env.HTTPS_ENABLED, false);
const cookieSecure = parseBoolean(
    process.env.ADMIN_COOKIE_SECURE,
    httpsEnabled
);

module.exports = {
    roles: {
        ADMIN: "ADMIN",
        VIEWER: "VIEWER"
    },
    adminStorePath: resolveFromBackendRoot(
        process.env.ADMIN_STORE_PATH,
        "data/admins.json"
    ),
    sessionSecret: getSessionSecret(),
    sessionTtlSeconds: parseSessionTtlSeconds(
        process.env.ADMIN_SESSION_TTL_SECONDS
    ),
    cookieName: process.env.ADMIN_COOKIE_NAME || "admin_session",
    cookieSecure,
    cookieSameSite: parseSameSite(
        process.env.ADMIN_COOKIE_SAME_SITE,
        cookieSecure ? "None" : "Lax"
    ),
    dashboardOrigins: parseOrigins(process.env.DASHBOARD_ORIGIN),
    httpsEnabled,
    httpsPort: parsePort(process.env.HTTPS_PORT, DEFAULT_HTTPS_PORT),
    tlsCertPath: resolveFromBackendRoot(
        process.env.TLS_CERT_PATH,
        "certs/server-cert.pem"
    ),
    tlsKeyPath: resolveFromBackendRoot(
        process.env.TLS_KEY_PATH,
        "certs/server-key.pem"
    )
};
