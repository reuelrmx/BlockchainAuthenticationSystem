"use strict";

const crypto = require("node:crypto");

const adminConfig = require("../config/adminConfig");

function base64UrlJson(value) {
    return Buffer.from(JSON.stringify(value), "utf8")
        .toString("base64url");
}

function sign(payload) {
    return crypto
        .createHmac("sha256", adminConfig.sessionSecret)
        .update(payload)
        .digest("base64url");
}

function secureCompare(left, right) {
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);

    if (leftBuffer.length !== rightBuffer.length) {
        return false;
    }

    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function createAdminSession(admin) {
    const issuedAtSeconds = Math.floor(Date.now() / 1000);
    const expiresAtSeconds =
        issuedAtSeconds + adminConfig.sessionTtlSeconds;
    const payload = base64UrlJson({
        sub: admin.username,
        role: admin.role,
        iat: issuedAtSeconds,
        exp: expiresAtSeconds
    });
    const signature = sign(payload);

    return {
        token: `${payload}.${signature}`,
        expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
        maxAgeSeconds: adminConfig.sessionTtlSeconds
    };
}

function verifyAdminSession(token) {
    if (typeof token !== "string" || token.trim() === "") {
        return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
        return null;
    }

    const [payload, signature] = parts;
    const expectedSignature = sign(payload);

    if (!secureCompare(signature, expectedSignature)) {
        return null;
    }

    let session;

    try {
        session = JSON.parse(
            Buffer.from(payload, "base64url").toString("utf8")
        );
    } catch {
        return null;
    }

    if (
        typeof session.sub !== "string" ||
        typeof session.role !== "string" ||
        !Object.values(adminConfig.roles).includes(session.role) ||
        typeof session.exp !== "number" ||
        Date.now() >= session.exp * 1000
    ) {
        return null;
    }

    return {
        username: session.sub,
        role: session.role,
        expiresAt: new Date(session.exp * 1000).toISOString()
    };
}

function serializeCookie(name, value, options = {}) {
    const segments = [
        `${name}=${value}`,
        "Path=/",
        "HttpOnly",
        `SameSite=${adminConfig.cookieSameSite}`
    ];

    if (options.maxAgeSeconds !== undefined) {
        segments.push(`Max-Age=${options.maxAgeSeconds}`);
    }

    if (options.expires) {
        segments.push(`Expires=${options.expires.toUTCString()}`);
    }

    if (adminConfig.cookieSecure) {
        segments.push("Secure");
    }

    return segments.join("; ");
}

function buildSessionCookie(token, maxAgeSeconds) {
    return serializeCookie(
        adminConfig.cookieName,
        token,
        {
            maxAgeSeconds
        }
    );
}

function buildClearSessionCookie() {
    return serializeCookie(
        adminConfig.cookieName,
        "",
        {
            maxAgeSeconds: 0,
            expires: new Date(0)
        }
    );
}

function getCookieValue(req, cookieName) {
    const cookieHeader = req.headers.cookie;

    if (typeof cookieHeader !== "string" || cookieHeader.trim() === "") {
        return null;
    }

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const separatorIndex = cookie.indexOf("=");

        if (separatorIndex === -1) {
            continue;
        }

        const name = cookie.slice(0, separatorIndex).trim();
        const value = cookie.slice(separatorIndex + 1).trim();

        if (name === cookieName) {
            return value;
        }
    }

    return null;
}

module.exports = {
    buildClearSessionCookie,
    buildSessionCookie,
    createAdminSession,
    getCookieValue,
    verifyAdminSession
};
