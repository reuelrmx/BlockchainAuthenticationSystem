"use strict";

const {
    evaluateTransaction
} = require("../services/fabricService");

const {
    createChallenge
} = require("../services/challengeService");

function isValidFabricDid(did) {
    return (
        typeof did === "string" &&
        /^did:fabric:[^\s]+$/.test(did)
    );
}

function isDeviceNotFoundError(error) {
    const message = error.message || "";

    return (
        message.includes("does not exist") ||
        message.includes("not found")
    );
}

async function getRegisteredDevice(did) {
    try {
        return await evaluateTransaction("GetDevice", did);
    } catch (error) {
        if (isDeviceNotFoundError(error)) {
            return null;
        }

        throw error;
    }
}

/**
 * POST /api/auth/challenge
 */
async function createAuthenticationChallenge(req, res, next) {
    try {
        const suppliedDid = req.body?.did;

        if (
            typeof suppliedDid !== "string" ||
            suppliedDid.trim() === ""
        ) {
            return res.status(400).json({
                success: false,
                message: "DID is required"
            });
        }

        const did = suppliedDid.trim();

        if (!isValidFabricDid(did)) {
            return res.status(400).json({
                success: false,
                message: "DID must use the did:fabric:<identifier> format"
            });
        }

        let device;

        try {
            device = await getRegisteredDevice(did);
        } catch (error) {
            console.error("Identity registry query failed:", error);

            return res.status(502).json({
                success: false,
                message: "Unable to query identity registry"
            });
        }

        if (!device) {
            return res.status(404).json({
                success: false,
                message: "Device identity does not exist"
            });
        }

        const status = String(device.status || "").toUpperCase();

        if (status === "SUSPENDED") {
            return res.status(403).json({
                success: false,
                message: "Suspended devices cannot receive authentication challenges"
            });
        }

        if (status === "REVOKED") {
            return res.status(403).json({
                success: false,
                message: "Revoked devices cannot receive authentication challenges"
            });
        }

        if (status !== "ACTIVE") {
            return res.status(403).json({
                success: false,
                message: "Only active devices can receive authentication challenges"
            });
        }

        const challenge = createChallenge(did);

        return res.status(201).json({
            success: true,
            message: "Authentication challenge generated",
            data: challenge
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    createAuthenticationChallenge
};
