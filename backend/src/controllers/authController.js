"use strict";

const {
    evaluateTransaction
} = require("../services/fabricService");

const {
    createChallenge,
    consumeChallenge,
    buildChallengePayload
} = require("../services/challengeService");

const {
    verifySignature
} = require("../services/signatureService");

function isValidFabricDid(did) {
    return (
        typeof did === "string" &&
        /^did:fabric:[^\s]+$/.test(did)
    );
}

function isValidChallengeId(challengeId) {
    return (
        typeof challengeId === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
            .test(challengeId)
    );
}

function isNonEmptyBase64(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return false;
    }

    const normalized = value.trim();

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
        return false;
    }

    if (normalized.length % 4 !== 0) {
        return false;
    }

    try {
        return Buffer.from(normalized, "base64").length > 0;
    } catch {
        return false;
    }
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

function denyAuthentication(res, statusCode, reason) {
    return res.status(statusCode).json({
        success: false,
        authenticated: false,
        decision: "DENIED",
        reason
    });
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

/**
 * POST /api/auth/verify
 */
async function verifyAuthenticationChallenge(req, res, next) {
    try {
        const suppliedDid = req.body?.did;
        const suppliedChallengeId = req.body?.challengeId;
        const suppliedSignature = req.body?.signature;

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

        if (
            typeof suppliedChallengeId !== "string" ||
            suppliedChallengeId.trim() === ""
        ) {
            return res.status(400).json({
                success: false,
                message: "Challenge ID is required"
            });
        }

        const challengeId = suppliedChallengeId.trim();

        if (!isValidChallengeId(challengeId)) {
            return res.status(400).json({
                success: false,
                message: "Challenge ID is invalid"
            });
        }

        if (!isNonEmptyBase64(suppliedSignature)) {
            return res.status(400).json({
                success: false,
                message: "Signature must be a non-empty Base64 string"
            });
        }

        const signature = suppliedSignature.trim();
        const consumption = consumeChallenge(challengeId);

        if (!consumption.consumed) {
            return denyAuthentication(
                res,
                401,
                "Invalid or expired authentication challenge"
            );
        }

        const challenge = consumption.challenge;

        if (challenge.did !== did) {
            console.warn(
                "Authentication denied because challenge DID did not match request DID",
                {
                    requestedDid: did,
                    challengeDid: challenge.did,
                    challengeId
                }
            );

            return denyAuthentication(
                res,
                401,
                "Invalid authentication challenge"
            );
        }

        let device;

        try {
            device = await getRegisteredDevice(did);
        } catch (error) {
            console.error(
                "Identity registry query failed during authentication verification:",
                {
                    message: error.message,
                    code: error.code,
                    details: error.details
                }
            );

            return res.status(502).json({
                success: false,
                authenticated: false,
                decision: "DENIED",
                reason: "Unable to verify device identity"
            });
        }

        if (!device) {
            return denyAuthentication(
                res,
                401,
                "Invalid authentication proof"
            );
        }

        const status = String(device.status || "").toUpperCase();

        if (status !== "ACTIVE") {
            return denyAuthentication(
                res,
                403,
                "Device is not active"
            );
        }

        if (
            typeof device.publicKey !== "string" ||
            device.publicKey.trim() === ""
        ) {
            console.warn(
                "Authentication denied because the Fabric device record has no usable public key",
                {
                    did,
                    challengeId
                }
            );

            return denyAuthentication(
                res,
                401,
                "Invalid authentication proof"
            );
        }

        const challengePayload = buildChallengePayload(challenge);
        const signatureValid = verifySignature(
            device.publicKey,
            challengePayload,
            signature
        );

        if (!signatureValid) {
            return denyAuthentication(
                res,
                401,
                "Invalid authentication proof"
            );
        }

        return res.status(200).json({
            success: true,
            authenticated: true,
            decision: "GRANTED",
            did
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    createAuthenticationChallenge,
    verifyAuthenticationChallenge
};
