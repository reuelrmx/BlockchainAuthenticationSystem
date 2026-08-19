"use strict";

const crypto = require("node:crypto");

const {
    evaluateTransaction
} = require("../services/fabricService");

const {
    createChallenge,
    consumeChallenge,
    buildChallengePayload
} = require("../services/challengeService");

const {
    DEFAULT_SPOOFING_CLASSIFICATION,
    recordAuthenticationEvent,
    verifyAuthentication
} = require("../services/auditService");

const spoofingConfig = require("../config/spoofingConfig");

const {
    getObservedNetworkContext
} = require("../services/networkContextService");

const {
    evaluateSpoofing
} = require("../services/spoofingService");

const {
    recordAuthenticationAttempt
} = require("../services/performanceMetricsService");

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

function getHttpStatusForContractDecision(result) {
    if (result.authenticated || result.decision === "GRANTED") {
        return 200;
    }

    if (
        result.reason === AUDIT_REASONS.DEVICE_NOT_ACTIVE ||
        result.reason === AUDIT_REASONS.MAC_MISMATCH ||
        result.reason === AUDIT_REASONS.IP_MISMATCH ||
        result.reason === AUDIT_REASONS.MAC_AND_IP_MISMATCH ||
        result.reason === AUDIT_REASONS.CONTEXT_INCOMPLETE
    ) {
        return 403;
    }

    return 401;
}

function getClientReasonForContractDecision(result) {
    if (result.authenticated || result.decision === "GRANTED") {
        return null;
    }

    if (
        result.reason === AUDIT_REASONS.MAC_MISMATCH ||
        result.reason === AUDIT_REASONS.IP_MISMATCH ||
        result.reason === AUDIT_REASONS.MAC_AND_IP_MISMATCH
    ) {
        return "Network context mismatch detected";
    }

    if (result.reason === AUDIT_REASONS.CONTEXT_INCOMPLETE) {
        return "Network context incomplete";
    }

    if (result.reason === AUDIT_REASONS.DEVICE_NOT_ACTIVE) {
        return "Device is not active";
    }

    return "Invalid authentication proof";
}

function buildContractResponseBody({
    did,
    contractResult,
    spoofingCheckDurationMs
}) {
    const authenticated = Boolean(contractResult.authenticated);
    const body = {
        success: authenticated,
        authenticated,
        decision: contractResult.decision,
        did,
        auditEventId: contractResult.eventId,
        spoofingClassification:
            contractResult.spoofingClassification ||
            DEFAULT_SPOOFING_CLASSIFICATION
    };

    if (contractResult.transactionId) {
        body.transactionId = contractResult.transactionId;
    }

    if (typeof spoofingCheckDurationMs === "number") {
        body.spoofingCheckDurationMs = spoofingCheckDurationMs;
    }

    if (!authenticated) {
        body.reason = getClientReasonForContractDecision(contractResult);
    }

    return body;
}

function elapsedMs(startedAt) {
    if (!startedAt) {
        return null;
    }

    return Number(process.hrtime.bigint() - startedAt) / 1_000_000;
}

function recordVerificationMetric({
    requestStartedAt,
    statusCode,
    body,
    spoofingCheckDurationMs
}) {
    recordAuthenticationAttempt({
        decision: body.decision,
        authenticated: body.authenticated === true,
        httpStatus: statusCode,
        totalAuthenticationDurationMs: elapsedMs(requestStartedAt),
        spoofingCheckDurationMs:
            body.spoofingCheckDurationMs ?? spoofingCheckDurationMs ?? null
    });
}

function sendVerificationResponse({
    res,
    statusCode,
    body,
    requestStartedAt,
    spoofingCheckDurationMs
}) {
    recordVerificationMetric({
        requestStartedAt,
        statusCode,
        body,
        spoofingCheckDurationMs
    });

    return res.status(statusCode).json(body);
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
    spoofingCheckDurationMs,
    requestStartedAt
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

        return sendVerificationResponse({
            res,
            statusCode: 502,
            requestStartedAt,
            body: {
                success: false,
                authenticated: false,
                decision: "DENIED",
                reason: "Authentication audit logging failed"
            }
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

    return sendVerificationResponse({
        res,
        statusCode,
        body,
        requestStartedAt,
        spoofingCheckDurationMs
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
        const requestStartedAt = process.hrtime.bigint();
        const suppliedDid = req.body?.did;
        const suppliedChallengeId = req.body?.challengeId;
        const suppliedSignature = req.body?.signature;
        let observedMacAddress = "";
        let observedIpAddress = "";

        if (
            typeof suppliedDid !== "string" ||
            suppliedDid.trim() === ""
        ) {
            return sendVerificationResponse({
                res,
                statusCode: 400,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    message: "DID is required"
                }
            });
        }

        const did = suppliedDid.trim();

        if (!isValidFabricDid(did)) {
            return sendVerificationResponse({
                res,
                statusCode: 400,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    message: "DID must use the did:fabric:<identifier> format"
                }
            });
        }

        if (
            typeof suppliedChallengeId !== "string" ||
            suppliedChallengeId.trim() === ""
        ) {
            return sendVerificationResponse({
                res,
                statusCode: 400,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    message: "Challenge ID is required"
                }
            });
        }

        const challengeId = suppliedChallengeId.trim();

        if (!isValidChallengeId(challengeId)) {
            return sendVerificationResponse({
                res,
                statusCode: 400,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    message: "Challenge ID is invalid"
                }
            });
        }

        if (!isNonEmptyBase64(suppliedSignature)) {
            return sendVerificationResponse({
                res,
                statusCode: 400,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    message: "Signature must be a non-empty Base64 string"
                }
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
                observedIpAddress,
                requestStartedAt
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
                observedIpAddress,
                requestStartedAt
            });
        }

        const challengePayload = buildChallengePayload(challenge);

        let observedNetworkContext;

        try {
            observedNetworkContext = await getObservedNetworkContext(req);
            observedMacAddress =
                observedNetworkContext.observedMacAddress || "";
            observedIpAddress =
                observedNetworkContext.observedIpAddress || "";
        } catch (error) {
            if (error.statusCode === 400) {
                return sendVerificationResponse({
                    res,
                    statusCode: 400,
                    requestStartedAt,
                    body: {
                        success: false,
                        authenticated: false,
                        decision: "DENIED",
                        message: error.message
                    }
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
                observedIpAddress,
                requestStartedAt
            });
        }

        let candidateSpoofingClassification =
            DEFAULT_SPOOFING_CLASSIFICATION;
        let spoofingCheckDurationMs = null;

        try {
            const device = await getRegisteredDevice(did);

            if (device) {
                const spoofingResult = evaluateSpoofing(
                    device,
                    observedNetworkContext
                );

                candidateSpoofingClassification =
                    spoofingResult.classification;
                spoofingCheckDurationMs =
                    spoofingResult.comparisonTimeMs;
                observedMacAddress =
                    spoofingResult.observedMacAddress || "";
                observedIpAddress =
                    spoofingResult.observedIpAddress || "";
            }
        } catch (error) {
            console.error(
                "Identity registry query failed during network-context classification:",
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
                clientReason: "Unable to evaluate network context",
                authenticated: false,
                observedMacAddress,
                observedIpAddress,
                requestStartedAt
            });
        }

        let contractResult;

        try {
            contractResult = await verifyAuthentication({
                eventId: crypto.randomUUID(),
                did,
                challengePayload,
                signatureBase64: signature,
                observedMacAddress,
                observedIpAddress,
                spoofingClassification: candidateSpoofingClassification,
                denyIncompleteNetworkContext:
                    spoofingConfig.denyIncompleteNetworkContext
            });
        } catch (error) {
            console.error(
                "AccessControl VerifyAuthentication transaction failed:",
                {
                    did,
                    challengeId,
                    message: error.message,
                    code: error.code,
                    details: error.details
                }
            );

            return sendVerificationResponse({
                res,
                statusCode: 502,
                requestStartedAt,
                body: {
                    success: false,
                    authenticated: false,
                    decision: "DENIED",
                    reason: "Unable to verify device identity"
                }
            });
        }

        const statusCode = getHttpStatusForContractDecision(contractResult);
        const body = buildContractResponseBody({
            did,
            contractResult,
            spoofingCheckDurationMs
        });

        return sendVerificationResponse({
            res,
            statusCode,
            body,
            requestStartedAt,
            spoofingCheckDurationMs
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    createAuthenticationChallenge,
    verifyAuthenticationChallenge
};
