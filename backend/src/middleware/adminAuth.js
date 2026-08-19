"use strict";

const adminConfig = require("../config/adminConfig");
const {
    getCookieValue,
    verifyAdminSession
} = require("../services/adminSessionService");
const {
    getAdminByUsername
} = require("../services/adminStore");

function sendUnauthorized(res) {
    return res.status(401).json({
        success: false,
        message: "Administrator authentication required"
    });
}

async function requireAdminAuthentication(req, res, next) {
    try {
        const token = getCookieValue(req, adminConfig.cookieName);
        const session = verifyAdminSession(token);

        if (!session) {
            return sendUnauthorized(res);
        }

        const admin = await getAdminByUsername(session.username);

        if (
            !admin ||
            admin.enabled === false ||
            admin.role !== session.role
        ) {
            return sendUnauthorized(res);
        }

        req.admin = {
            username: admin.username,
            role: admin.role,
            expiresAt: session.expiresAt
        };

        return next();
    } catch (error) {
        return next(error);
    }
}

function requireAdminRole(...allowedRoles) {
    const allowed = new Set(allowedRoles);

    return (req, res, next) => {
        if (!req.admin) {
            return sendUnauthorized(res);
        }

        if (!allowed.has(req.admin.role)) {
            return res.status(403).json({
                success: false,
                message: "Insufficient administrator role"
            });
        }

        return next();
    };
}

module.exports = {
    requireAdminAuthentication,
    requireAdminRole
};
