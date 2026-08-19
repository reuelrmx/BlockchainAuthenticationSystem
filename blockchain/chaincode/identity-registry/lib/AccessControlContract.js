"use strict";

const crypto = require("node:crypto");
const { Contract } = require("fabric-contract-api");

const DEFAULT_SPOOFING_CLASSIFICATION = "NOT_EVALUATED";

const CRYPTOGRAPHIC_DENIAL_CLASSIFICATION = "NOT_EVALUATED";

const SPOOFING_CLASSIFICATIONS = new Set([
    "NONE",
    "NOT_EVALUATED",
    "CONTEXT_INCOMPLETE",
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH"
]);

const SPOOFING_DENIAL_REASONS = new Set([
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH"
]);

class AccessControlContract extends Contract {
    constructor() {
        super("AccessControlContract");
    }

    _requireValue(value, fieldName) {
        if (typeof value !== "string" || value.trim() === "") {
            throw new Error(`${fieldName} is required`);
        }
    }

    _getTransactionTimestamp(ctx) {
        const timestamp = ctx.stub.getTxTimestamp();

        const seconds =
            typeof timestamp.seconds === "object"
                ? timestamp.seconds.toNumber()
                : Number(timestamp.seconds);

        const milliseconds =
            seconds * 1000 + Math.floor(timestamp.nanos / 1000000);

        return new Date(milliseconds).toISOString();
    }

    _createAuthenticationEventKey(ctx, eventId) {
        return ctx.stub.createCompositeKey("AUTH_EVENT", [eventId]);
    }

    _createAuthenticationEventByDeviceKey(ctx, did, eventId) {
        return ctx.stub.createCompositeKey(
            "AUTH_EVENT_BY_DEVICE",
            [did, eventId]
        );
    }

    _createDeviceKey(ctx, did) {
        return ctx.stub.createCompositeKey("DEVICE", [did]);
    }

    _normalizeOptionalValue(value) {
        if (typeof value !== "string" || value.trim() === "") {
            return null;
        }

        return value.trim();
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
            this._normalizeOptionalValue(spoofingClassification) ||
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

    async _authenticationEventExists(ctx, eventId) {
        const key = this._createAuthenticationEventKey(ctx, eventId);
        const bytes = await ctx.stub.getState(key);

        return Boolean(bytes && bytes.length > 0);
    }

    async _getDevice(ctx, did) {
        const deviceKey = this._createDeviceKey(ctx, did);
        const deviceBytes = await ctx.stub.getState(deviceKey);

        if (!deviceBytes || deviceBytes.length === 0) {
            return null;
        }

        return JSON.parse(deviceBytes.toString());
    }

    async _putAuthenticationEvent(ctx, event) {
        const eventKey = this._createAuthenticationEventKey(
            ctx,
            event.eventId
        );

        const deviceEventKey =
            this._createAuthenticationEventByDeviceKey(
                ctx,
                event.did,
                event.eventId
            );

        await ctx.stub.putState(
            eventKey,
            Buffer.from(JSON.stringify(event))
        );

        await ctx.stub.putState(
            deviceEventKey,
            Buffer.from(JSON.stringify({
                eventId: event.eventId
            }))
        );

        ctx.stub.setEvent(
            "AuthenticationEventRecorded",
            Buffer.from(JSON.stringify({
                eventId: event.eventId,
                did: event.did,
                decision: event.decision,
                reason: event.reason,
                timestamp: event.timestamp,
                transactionId: event.transactionId
            }))
        );
    }

    _buildAuthenticationEvent({
        ctx,
        eventId,
        did,
        decision,
        reason,
        observedMacAddress,
        observedIpAddress,
        spoofingClassification
    }) {
        return {
            docType: "authenticationEvent",
            eventId,
            did,
            timestamp: this._getTransactionTimestamp(ctx),
            decision,
            reason,
            observedMacAddress:
                this._normalizeOptionalValue(observedMacAddress),
            observedIpAddress:
                this._normalizeOptionalValue(observedIpAddress),
            spoofingClassification,
            recordedBy: ctx.clientIdentity.getID(),
            transactionId: ctx.stub.getTxID()
        };
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
        const normalizedDid = did.trim();
        const normalizedDecision = this._normalizeDecision(decision);
        const normalizedReason = reason.trim().toUpperCase();
        const normalizedSpoofingClassification =
            this._normalizeSpoofingClassification(spoofingClassification);

        const exists = await this._authenticationEventExists(
            ctx,
            normalizedEventId
        );

        if (exists) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const event = this._buildAuthenticationEvent({
            ctx,
            eventId: normalizedEventId,
            did: normalizedDid,
            decision: normalizedDecision,
            reason: normalizedReason,
            observedMacAddress,
            observedIpAddress,
            spoofingClassification: normalizedSpoofingClassification
        });

        await this._putAuthenticationEvent(ctx, event);

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
        const denyIncomplete = this._parseBoolean(
            denyIncompleteNetworkContext,
            "Deny incomplete network context"
        );

        const exists = await this._authenticationEventExists(
            ctx,
            normalizedEventId
        );

        if (exists) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const device = await this._getDevice(ctx, normalizedDid);
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
        } else if (
            SPOOFING_DENIAL_REASONS.has(normalizedSpoofingClassification)
        ) {
            reason = normalizedSpoofingClassification;
            finalSpoofingClassification = normalizedSpoofingClassification;
        } else if (
            normalizedSpoofingClassification === "CONTEXT_INCOMPLETE" &&
            denyIncomplete
        ) {
            reason = "CONTEXT_INCOMPLETE";
            finalSpoofingClassification = normalizedSpoofingClassification;
        } else {
            decision = "GRANTED";
            reason = "VALID_SIGNATURE";
            finalSpoofingClassification = normalizedSpoofingClassification;
        }

        const event = this._buildAuthenticationEvent({
            ctx,
            eventId: normalizedEventId,
            did: normalizedDid,
            decision,
            reason,
            observedMacAddress,
            observedIpAddress,
            spoofingClassification: finalSpoofingClassification
        });

        await this._putAuthenticationEvent(ctx, event);

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

        const key = this._createAuthenticationEventKey(
            ctx,
            eventId.trim()
        );

        const bytes = await ctx.stub.getState(key);

        if (!bytes || bytes.length === 0) {
            throw new Error(
                `Authentication event ${eventId} does not exist`
            );
        }

        return bytes.toString();
    }

    async GetAllAuthenticationEvents(ctx) {
        const iterator = await ctx.stub.getStateByPartialCompositeKey(
            "AUTH_EVENT",
            []
        );

        const events = [];

        try {
            while (true) {
                const result = await iterator.next();

                if (result.value && result.value.value) {
                    const value = result.value.value.toString("utf8");

                    if (value) {
                        events.push(JSON.parse(value));
                    }
                }

                if (result.done) {
                    break;
                }
            }
        } finally {
            await iterator.close();
        }

        events.sort(
            (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
        );

        return JSON.stringify(events);
    }

    async GetAuthenticationEventsByDevice(ctx, did) {
        this._requireValue(did, "DID");

        const normalizedDid = did.trim();
        const iterator = await ctx.stub.getStateByPartialCompositeKey(
            "AUTH_EVENT_BY_DEVICE",
            [normalizedDid]
        );

        const events = [];

        try {
            while (true) {
                const result = await iterator.next();

                if (result.value && result.value.key) {
                    const compositeKey =
                        ctx.stub.splitCompositeKey(result.value.key);
                    const eventId = compositeKey.attributes[1];

                    if (eventId) {
                        const eventJson =
                            await this.GetAuthenticationEvent(
                                ctx,
                                eventId
                            );

                        events.push(JSON.parse(eventJson));
                    }
                }

                if (result.done) {
                    break;
                }
            }
        } finally {
            await iterator.close();
        }

        events.sort(
            (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
        );

        return JSON.stringify(events);
    }
}

module.exports = AccessControlContract;
