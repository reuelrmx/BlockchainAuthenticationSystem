"use strict";

const {
    buildClearSessionCookie,
    buildSessionCookie,
    createAdminSession
} = require("../services/adminSessionService");
const {
    verifyAdminCredentials
} = require("../services/adminStore");

async function login(req, res, next) {
    try {
        const username = req.body?.username;
        const password = req.body?.password;

        if (
            typeof username !== "string" ||
            username.trim() === "" ||
            typeof password !== "string" ||
            password === ""
        ) {
            return res.status(400).json({
                success: false,
                message: "Username and password are required"
            });
        }

        const admin = await verifyAdminCredentials(username, password);

        if (!admin) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const session = createAdminSession(admin);

        res.setHeader(
            "Set-Cookie",
            buildSessionCookie(session.token, session.maxAgeSeconds)
        );

        return res.status(200).json({
            success: true,
            message: "Administrator authenticated",
            data: {
                admin,
                expiresAt: session.expiresAt
            }
        });
    } catch (error) {
        next(error);
    }
}

async function logout(req, res, next) {
    try {
        res.setHeader("Set-Cookie", buildClearSessionCookie());

        return res.status(200).json({
            success: true,
            message: "Administrator session cleared"
        });
    } catch (error) {
        next(error);
    }
}

async function getCurrentAdmin(req, res) {
    return res.status(200).json({
        success: true,
        data: {
            admin: req.admin
        }
    });
}

module.exports = {
    getCurrentAdmin,
    login,
    logout
};
