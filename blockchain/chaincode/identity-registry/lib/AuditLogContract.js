"use strict";

const { Contract } = require("fabric-contract-api");

const {
    DEFAULT_SPOOFING_CLASSIFICATION,
    authenticationEventExists,
    buildAuthenticationEvent,
    buildGenericAuditEvent,
    getAllAuthenticationEvents,
    getAuthenticationEvent,
    getAuthenticationEventsByDevice,
    putAuthenticationEvent,
    putGenericAuditEvent,
    requireValue
} = require("./auditState");
const {
    assertFabricAdministrator
} = require("./authorization");

const DECISIONS = new Set([
    "GRANTED",
    "DENIED"
]);

const SPOOFING_CLASSIFICATIONS = new Set([
    "NONE",
    "NOT_EVALUATED",
    "CONTEXT_INCOMPLETE",
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH"
]);

function normalizeDecision(decision) {
    const normalized = decision.trim().toUpperCase();

    if (!DECISIONS.has(normalized)) {
        throw new Error("Decision must be GRANTED or DENIED");
    }

    return normalized;
}

function normalizeSpoofingClassification(spoofingClassification) {
    if (
        typeof spoofingClassification !== "string" ||
        spoofingClassification.trim() === ""
    ) {
        return DEFAULT_SPOOFING_CLASSIFICATION;
    }

    const normalized = spoofingClassification.trim().toUpperCase();

    if (!SPOOFING_CLASSIFICATIONS.has(normalized)) {
        throw new Error("Spoofing classification is invalid");
    }

    return normalized;
}

class AuditLogContract extends Contract {
    constructor() {
        super("AuditLogContract");
    }

    /**
     * Records an immutable authentication decision/audit record.
     */
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
        requireValue(eventId, "Event ID");
        requireValue(did, "DID");
        requireValue(decision, "Decision");
        requireValue(reason, "Reason");

        const normalizedEventId = eventId.trim();

        if (await authenticationEventExists(ctx, normalizedEventId)) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const event = buildAuthenticationEvent({
            ctx,
            eventId: normalizedEventId,
            did: did.trim(),
            decision: normalizeDecision(decision),
            reason: reason.trim().toUpperCase(),
            observedMacAddress,
            observedIpAddress,
            spoofingClassification:
                normalizeSpoofingClassification(spoofingClassification)
        });

        await putAuthenticationEvent(ctx, event);

        return JSON.stringify(event);
    }

    /**
     * Records a device revocation audit event.
     */
    async LogRevocationEvent(ctx, eventId, did, reason) {
        assertFabricAdministrator(ctx, "LogRevocationEvent");
        requireValue(eventId, "Event ID");
        requireValue(did, "DID");
        requireValue(reason, "Reason");

        const event = buildGenericAuditEvent(
            ctx,
            "DEVICE_REVOKED",
            {
                eventId: eventId.trim(),
                did: did.trim(),
                details: {
                    reason: reason.trim()
                }
            }
        );

        await putGenericAuditEvent(ctx, event);

        return JSON.stringify(event);
    }

    /**
     * Records a spoofing incident audit event without storing raw MAC data.
     */
    async LogSpoofingIncident(
        ctx,
        eventId,
        did,
        spoofingClassification,
        observedMacAddress,
        observedIpAddress,
        reason
    ) {
        requireValue(eventId, "Event ID");
        requireValue(did, "DID");
        requireValue(spoofingClassification, "Spoofing classification");

        const event = buildGenericAuditEvent(
            ctx,
            "SPOOFING_INCIDENT",
            {
                eventId: eventId.trim(),
                did: did.trim(),
                details: {
                    reason: reason ? reason.trim().toUpperCase() : null,
                    observedIpAddress:
                        observedIpAddress && observedIpAddress.trim()
                            ? observedIpAddress.trim()
                            : null,
                    spoofingClassification:
                        normalizeSpoofingClassification(
                            spoofingClassification
                        ),
                    observedMacAddressStored: false
                }
            }
        );

        if (observedMacAddress && observedMacAddress.trim()) {
            event.details.observedMacAddressHashOnly = true;
        }

        await putGenericAuditEvent(ctx, event);

        return JSON.stringify(event);
    }

    /**
     * Records a policy update audit event.
     */
    async LogPolicyUpdate(ctx, eventId, policyHash) {
        assertFabricAdministrator(ctx, "LogPolicyUpdate");
        requireValue(eventId, "Event ID");
        requireValue(policyHash, "Policy hash");

        const event = buildGenericAuditEvent(
            ctx,
            "ACCESS_POLICY_UPDATED",
            {
                eventId: eventId.trim(),
                details: {
                    policyHash: policyHash.trim()
                }
            }
        );

        await putGenericAuditEvent(ctx, event);

        return JSON.stringify(event);
    }

    async GetAuthenticationEvent(ctx, eventId) {
        requireValue(eventId, "Event ID");

        return getAuthenticationEvent(ctx, eventId);
    }

    async GetAllAuthenticationEvents(ctx) {
        return getAllAuthenticationEvents(ctx);
    }

    async GetEventsByDevice(ctx, did) {
        requireValue(did, "DID");

        return getAuthenticationEventsByDevice(ctx, did.trim());
    }
}

module.exports = AuditLogContract;
