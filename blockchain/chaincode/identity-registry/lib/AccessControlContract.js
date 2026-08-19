"use strict";

const crypto = require("node:crypto");
const { Contract } = require("fabric-contract-api");

const {
    DEFAULT_SPOOFING_CLASSIFICATION,
    authenticationEventExists,
    buildAuthenticationEvent,
    buildGenericAuditEvent,
    getAllAuthenticationEvents,
    getAuthenticationEvent,
    getAuthenticationEventsByDevice,
    getTransactionTimestamp,
    normalizeOptionalValue,
    putAuthenticationEvent,
    putGenericAuditEvent,
    requireValue
} = require("./auditState");
const {
    assertFabricAdministrator
} = require("./authorization");

const CRYPTOGRAPHIC_DENIAL_CLASSIFICATION = "NOT_EVALUATED";

const SPOOFING_CLASSIFICATIONS = new Set([
    "NONE",
    "NOT_EVALUATED",
    "CONTEXT_INCOMPLETE",
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH"
]);

const DEFAULT_ACCESS_POLICY = Object.freeze({
    requireMacContext: true,
    requireIpContext: true,
    denyIncompleteNetworkContext: false,
    macMismatchAction: "DENY",
    ipMismatchAction: "DENY"
});

class AccessControlContract extends Contract {
    constructor() {
        super("AccessControlContract");
    }

    _requireValue(value, fieldName) {
        requireValue(value, fieldName);
    }

    _getTransactionTimestamp(ctx) {
        return getTransactionTimestamp(ctx);
    }

    _createDeviceKey(ctx, did) {
        return ctx.stub.createCompositeKey("DEVICE", [did]);
    }

    _createAccessPolicyKey(ctx) {
        return ctx.stub.createCompositeKey("ACCESS_POLICY", ["GLOBAL"]);
    }

    _normalizeDecision(decision) {
        const normalized = decision.trim().toUpperCase();

        if (normalized !== "GRANTED" && normalized !== "DENIED") {
            throw new Error("Decision must be GRANTED or DENIED");
        }

        return normalized;
    }

    _normalizeSpoofingClassification(spoofingClassification) {
        const normalized =
            normalizeOptionalValue(spoofingClassification) ||
            DEFAULT_SPOOFING_CLASSIFICATION;
        const upper = normalized.trim().toUpperCase();

        if (!SPOOFING_CLASSIFICATIONS.has(upper)) {
            throw new Error("Spoofing classification is invalid");
        }

        return upper;
    }

    _parseBoolean(value, fieldName) {
        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {
            return false;
        }

        const normalized = String(value).trim().toLowerCase();

        if (["true", "1", "yes", "on"].includes(normalized)) {
            return true;
        }

        if (["false", "0", "no", "off"].includes(normalized)) {
            return false;
        }

        throw new Error(`${fieldName} must be true or false`);
    }

    _normalizeAction(value, fieldName) {
        const normalized = String(value || "").trim().toUpperCase();

        if (normalized === "DENY" || normalized === "ALLOW") {
            return normalized;
        }

        throw new Error(`${fieldName} must be DENY or ALLOW`);
    }

    _stableStringify(value) {
        if (Array.isArray(value)) {
            return `[${value.map((entry) =>
                this._stableStringify(entry)
            ).join(",")}]`;
        }

        if (value && typeof value === "object") {
            return `{${Object.keys(value)
                .sort()
                .map((key) =>
                    `${JSON.stringify(key)}:${this._stableStringify(value[key])}`
                )
                .join(",")}}`;
        }

        return JSON.stringify(value);
    }

    _hashPolicy(policy) {
        return crypto
            .createHash("sha256")
            .update(this._stableStringify(policy))
            .digest("hex");
    }

    _normalizeAccessPolicy(input) {
        const suppliedPolicy =
            typeof input === "string" ? JSON.parse(input) : input;
        const mergedPolicy = {
            ...DEFAULT_ACCESS_POLICY,
            ...(suppliedPolicy || {})
        };

        return {
            requireMacContext: Boolean(mergedPolicy.requireMacContext),
            requireIpContext: Boolean(mergedPolicy.requireIpContext),
            denyIncompleteNetworkContext:
                Boolean(mergedPolicy.denyIncompleteNetworkContext),
            macMismatchAction: this._normalizeAction(
                mergedPolicy.macMismatchAction,
                "MAC mismatch action"
            ),
            ipMismatchAction: this._normalizeAction(
                mergedPolicy.ipMismatchAction,
                "IP mismatch action"
            )
        };
    }

    _verifySignature(publicKeyPem, challengePayload, signatureBase64) {
        if (
            typeof publicKeyPem !== "string" ||
            publicKeyPem.trim() === "" ||
            typeof challengePayload !== "string" ||
            challengePayload === "" ||
            typeof signatureBase64 !== "string" ||
            signatureBase64.trim() === ""
        ) {
            return false;
        }

        try {
            const verifier = crypto.createVerify("SHA256");
            verifier.update(challengePayload);
            verifier.end();

            return verifier.verify(
                publicKeyPem,
                signatureBase64,
                "base64"
            );
        } catch {
            return false;
        }
    }

    async _getDevice(ctx, did) {
        const deviceKey = this._createDeviceKey(ctx, did);
        const deviceBytes = await ctx.stub.getState(deviceKey);

        if (!deviceBytes || deviceBytes.length === 0) {
            return null;
        }

        return JSON.parse(deviceBytes.toString());
    }

    async _getAccessPolicy(ctx) {
        const key = this._createAccessPolicyKey(ctx);
        const policyBytes = await ctx.stub.getState(key);

        if (!policyBytes || policyBytes.length === 0) {
            return {
                ...DEFAULT_ACCESS_POLICY,
                policyId: "GLOBAL",
                source: "default",
                policyHash: this._hashPolicy(DEFAULT_ACCESS_POLICY)
            };
        }

        return JSON.parse(policyBytes.toString());
    }

    _getSpoofingDenialReason(classification, policy) {
        if (
            classification === "MAC_AND_IP_MISMATCH" &&
            (
                policy.macMismatchAction === "DENY" ||
                policy.ipMismatchAction === "DENY"
            )
        ) {
            return "MAC_AND_IP_MISMATCH";
        }

        if (
            classification === "MAC_MISMATCH" &&
            policy.macMismatchAction === "DENY"
        ) {
            return "MAC_MISMATCH";
        }

        if (
            classification === "IP_MISMATCH" &&
            policy.ipMismatchAction === "DENY"
        ) {
            return "IP_MISMATCH";
        }

        if (
            classification === "CONTEXT_INCOMPLETE" &&
            policy.denyIncompleteNetworkContext
        ) {
            return "CONTEXT_INCOMPLETE";
        }

        return null;
    }

    /**
     * Returns the global prototype authentication policy.
     */
    async GetAccessPolicy(ctx) {
        return JSON.stringify(await this._getAccessPolicy(ctx));
    }

    /**
     * Updates the global authentication policy.
     *
     * Only Fabric administrator identities may mutate this policy.
     */
    async UpdateAccessPolicy(ctx, policyJson) {
        assertFabricAdministrator(ctx, "UpdateAccessPolicy");
        requireValue(policyJson, "Access policy");

        const policy = this._normalizeAccessPolicy(policyJson);
        const timestamp = this._getTransactionTimestamp(ctx);
        const storedPolicy = {
            ...policy,
            policyId: "GLOBAL",
            source: "ledger",
            updatedAt: timestamp,
            updatedBy: ctx.clientIdentity.getID(),
            transactionId: ctx.stub.getTxID(),
            policyHash: this._hashPolicy(policy)
        };

        await ctx.stub.putState(
            this._createAccessPolicyKey(ctx),
            Buffer.from(JSON.stringify(storedPolicy))
        );

        await putGenericAuditEvent(
            ctx,
            buildGenericAuditEvent(
                ctx,
                "ACCESS_POLICY_UPDATED",
                {
                    eventId: `policy-${ctx.stub.getTxID()}`,
                    details: {
                        policyHash: storedPolicy.policyHash
                    }
                }
            )
        );

        ctx.stub.setEvent(
            "AccessPolicyUpdated",
            Buffer.from(JSON.stringify({
                policyId: storedPolicy.policyId,
                policyHash: storedPolicy.policyHash,
                updatedAt: storedPolicy.updatedAt,
                transactionId: storedPolicy.transactionId
            }))
        );

        return JSON.stringify(storedPolicy);
    }

    async LogAuthenticationEvent(
        ctx,
        eventId,
        did,
        decision,
        reason,
        observedMacAddress,
        observedIpAddress,
        spoofingClassification
    ) {
        this._requireValue(eventId, "Event ID");
        this._requireValue(did, "DID");
        this._requireValue(decision, "Decision");
        this._requireValue(reason, "Reason");

        const normalizedEventId = eventId.trim();
        const normalizedDecision = this._normalizeDecision(decision);
        const normalizedSpoofingClassification =
            this._normalizeSpoofingClassification(spoofingClassification);

        const exists = await authenticationEventExists(
            ctx,
            normalizedEventId
        );

        if (exists) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const event = buildAuthenticationEvent({
            ctx,
            eventId: normalizedEventId,
            did: did.trim(),
            decision: normalizedDecision,
            reason: reason.trim().toUpperCase(),
            observedMacAddress,
            observedIpAddress,
            spoofingClassification: normalizedSpoofingClassification
        });

        await putAuthenticationEvent(ctx, event);

        return JSON.stringify(event);
    }

    async VerifyAuthentication(
        ctx,
        eventId,
        did,
        challengePayload,
        signatureBase64,
        observedMacAddress,
        observedIpAddress,
        spoofingClassification,
        denyIncompleteNetworkContext
    ) {
        this._requireValue(eventId, "Event ID");
        this._requireValue(did, "DID");
        this._requireValue(challengePayload, "Challenge payload");
        this._requireValue(signatureBase64, "Signature");

        const normalizedEventId = eventId.trim();
        const normalizedDid = did.trim();
        const normalizedSpoofingClassification =
            this._normalizeSpoofingClassification(spoofingClassification);
        const legacyDenyIncomplete = this._parseBoolean(
            denyIncompleteNetworkContext,
            "Deny incomplete network context"
        );

        const exists = await authenticationEventExists(
            ctx,
            normalizedEventId
        );

        if (exists) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const device = await this._getDevice(ctx, normalizedDid);
        const policy = await this._getAccessPolicy(ctx);
        const effectivePolicy = {
            ...policy,
            denyIncompleteNetworkContext:
                policy.denyIncompleteNetworkContext ||
                legacyDenyIncomplete
        };
        let decision = "DENIED";
        let reason = "UNKNOWN_DEVICE";
        let finalSpoofingClassification =
            CRYPTOGRAPHIC_DENIAL_CLASSIFICATION;

        if (!device) {
            reason = "UNKNOWN_DEVICE";
        } else if (String(device.status || "").toUpperCase() !== "ACTIVE") {
            reason = "DEVICE_NOT_ACTIVE";
        } else if (
            typeof device.publicKey !== "string" ||
            device.publicKey.trim() === ""
        ) {
            reason = "PUBLIC_KEY_UNAVAILABLE";
        } else if (!this._verifySignature(
            device.publicKey,
            challengePayload,
            signatureBase64.trim()
        )) {
            reason = "INVALID_SIGNATURE";
        } else {
            const spoofingDenialReason = this._getSpoofingDenialReason(
                normalizedSpoofingClassification,
                effectivePolicy
            );

            finalSpoofingClassification =
                normalizedSpoofingClassification;

            if (spoofingDenialReason) {
                reason = spoofingDenialReason;
            } else {
                decision = "GRANTED";
                reason = "VALID_SIGNATURE";
            }
        }

        const event = buildAuthenticationEvent({
            ctx,
            eventId: normalizedEventId,
            did: normalizedDid,
            decision,
            reason,
            observedMacAddress,
            observedIpAddress,
            spoofingClassification: finalSpoofingClassification
        });

        await putAuthenticationEvent(ctx, event);

        return JSON.stringify({
            eventId: event.eventId,
            did: event.did,
            authenticated: decision === "GRANTED",
            decision,
            reason,
            spoofingClassification: event.spoofingClassification,
            transactionId: event.transactionId
        });
    }

    async GetAuthenticationEvent(ctx, eventId) {
        this._requireValue(eventId, "Event ID");

        return getAuthenticationEvent(ctx, eventId);
    }

    async GetAllAuthenticationEvents(ctx) {
        return getAllAuthenticationEvents(ctx);
    }

    async GetAuthenticationEventsByDevice(ctx, did) {
        this._requireValue(did, "DID");

        return getAuthenticationEventsByDevice(ctx, did.trim());
    }
}

module.exports = AccessControlContract;
