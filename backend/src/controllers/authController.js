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

const {
    DEFAULT_SPOOFING_CLASSIFICATION,
    recordAuthenticationEvent
} = require("../services/auditService");

const {
    getObservedNetworkContext
} = require("../services/networkContextService");

const {
    evaluateSpoofing
} = require("../services/spoofingService");

const AUDIT_REASONS = {
    VALID_SIGNATURE: "VALID_SIGNATURE",
    INVALID_SIGNATURE: "INVALID_SIGNATURE",
    DEVICE_NOT_ACTIVE: "DEVICE_NOT_ACTIVE",
    INVALID_CHALLENGE: "INVALID_CHALLENGE",
    EXPIRED_CHALLENGE: "EXPIRED_CHALLENGE",
    DID_MISMATCH: "DID_MISMATCH",
    MAC_MISMATCH: "MAC_MISMATCH",
    IP_MISMATCH: "IP_MISMATCH",
    MAC_AND_IP_MISMATCH: "MAC_AND_IP_MISMATCH",
    CONTEXT_INCOMPLETE: "CONTEXT_INCOMPLETE",
    UNKNOWN_DEVICE: "UNKNOWN_DEVICE",
    PUBLIC_KEY_UNAVAILABLE: "PUBLIC_KEY_UNAVAILABLE",
    INTERNAL_VERIFICATION_ERROR: "INTERNAL_VERIFICATION_ERROR"
};

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

function getChallengeAuditReason(consumptionReason) {
    if (consumptionReason === "CHALLENGE_EXPIRED") {
        return AUDIT_REASONS.EXPIRED_CHALLENGE;
    }

    return AUDIT_REASONS.INVALID_CHALLENGE;
}

async function respondWithAuditedDecision({
    res,
    statusCode,
    did,
    decision,
    auditReason,
    clientReason,
    authenticated,
    observedMacAddress,
    observedIpAddress,
    spoofingClassification = DEFAULT_SPOOFING_CLASSIFICATION,
    spoofingCheckDurationMs
}) {
    let auditEvent;

    try {
        auditEvent = await recordAuthenticationEvent({
            did,
            decision,
            reason: auditReason,
            observedMacAddress,
            observedIpAddress,
            spoofingClassification
        });
    } catch (error) {
        console.error(
            "Authentication audit logging failed:",
            {
                did,
                decision,
                reason: auditReason,
                message: error.message,
                code: error.code,
                details: error.details
            }
        );

        return res.status(502).json({
            success: false,
            authenticated: false,
            decision: "DENIED",
            reason: "Authentication audit logging failed"
        });
    }

    const body = {
        success: authenticated,
        authenticated,
        decision,
        did,
        auditEventId: auditEvent.eventId,
        spoofingClassification
    };

    if (typeof spoofingCheckDurationMs === "number") {
        body.spoofingCheckDurationMs = spoofingCheckDurationMs;
    }

    if (!authenticated) {
        body.reason = clientReason;
    }

    return res.status(statusCode).json(body);
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
        let observedMacAddress = "";
        let observedIpAddress = "";

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
            return respondWithAuditedDecision({
                res,
                statusCode: 401,
                did,
                decision: "DENIED",
                auditReason: getChallengeAuditReason(consumption.reason),
                clientReason: "Invalid or expired authentication challenge",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
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

            return respondWithAuditedDecision({
                res,
                statusCode: 401,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.DID_MISMATCH,
                clientReason: "Invalid authentication challenge",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
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

            return respondWithAuditedDecision({
                res,
                statusCode: 502,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.INTERNAL_VERIFICATION_ERROR,
                clientReason: "Unable to verify device identity",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
        }

        if (!device) {
            return respondWithAuditedDecision({
                res,
                statusCode: 401,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.UNKNOWN_DEVICE,
                clientReason: "Invalid authentication proof",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
        }

        const status = String(device.status || "").toUpperCase();

        if (status !== "ACTIVE") {
            return respondWithAuditedDecision({
                res,
                statusCode: 403,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.DEVICE_NOT_ACTIVE,
                clientReason: "Device is not active",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
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

            return respondWithAuditedDecision({
                res,
                statusCode: 401,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.PUBLIC_KEY_UNAVAILABLE,
                clientReason: "Invalid authentication proof",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
        }

        const challengePayload = buildChallengePayload(challenge);
        const signatureValid = verifySignature(
            device.publicKey,
            challengePayload,
            signature
        );

        if (!signatureValid) {
            return respondWithAuditedDecision({
                res,
                statusCode: 401,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.INVALID_SIGNATURE,
                clientReason: "Invalid authentication proof",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
        }

        let observedNetworkContext;

        try {
            observedNetworkContext = await getObservedNetworkContext(req);
            observedMacAddress =
                observedNetworkContext.observedMacAddress || "";
            observedIpAddress =
                observedNetworkContext.observedIpAddress || "";
        } catch (error) {
            if (error.statusCode === 400) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            console.error(
                "Network context extraction failed:",
                {
                    did,
                    message: error.message
                }
            );

            return respondWithAuditedDecision({
                res,
                statusCode: 502,
                did,
                decision: "DENIED",
                auditReason: AUDIT_REASONS.INTERNAL_VERIFICATION_ERROR,
                clientReason: "Unable to evaluate network context",
                authenticated: false,
                observedMacAddress,
                observedIpAddress
            });
        }

        const spoofingResult = evaluateSpoofing(
            device,
            observedNetworkContext
        );

        if (
            spoofingResult.detected ||
            spoofingResult.deniedForIncompleteContext
        ) {
            const reason = spoofingResult.detected
                ? spoofingResult.classification
                : AUDIT_REASONS.CONTEXT_INCOMPLETE;

            return respondWithAuditedDecision({
                res,
                statusCode: 403,
                did,
                decision: "DENIED",
                auditReason: reason,
                clientReason: spoofingResult.detected
                    ? "Network context mismatch detected"
                    : "Network context incomplete",
                authenticated: false,
                observedMacAddress:
                    spoofingResult.observedMacAddress || "",
                observedIpAddress:
                    spoofingResult.observedIpAddress || "",
                spoofingClassification: spoofingResult.classification,
                spoofingCheckDurationMs:
                    spoofingResult.comparisonTimeMs
            });
        }

        return respondWithAuditedDecision({
            res,
            statusCode: 200,
            did,
            decision: "GRANTED",
            auditReason: AUDIT_REASONS.VALID_SIGNATURE,
            authenticated: true,
            observedMacAddress:
                spoofingResult.observedMacAddress || "",
            observedIpAddress:
                spoofingResult.observedIpAddress || "",
            spoofingClassification: spoofingResult.classification,
            spoofingCheckDurationMs:
                spoofingResult.comparisonTimeMs
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    createAuthenticationChallenge,
    verifyAuthenticationChallenge
};
