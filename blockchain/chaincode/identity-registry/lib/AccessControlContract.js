"use strict";

const { Contract } = require("fabric-contract-api");

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

    async _authenticationEventExists(ctx, eventId) {
        const key = this._createAuthenticationEventKey(ctx, eventId);
        const bytes = await ctx.stub.getState(key);

        return Boolean(bytes && bytes.length > 0);
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
            this._normalizeOptionalValue(spoofingClassification) ||
            "NOT_EVALUATED";

        const exists = await this._authenticationEventExists(
            ctx,
            normalizedEventId
        );

        if (exists) {
            throw new Error(
                `Authentication event ${normalizedEventId} already exists`
            );
        }

        const transactionId = ctx.stub.getTxID();
        const timestamp = this._getTransactionTimestamp(ctx);

        const event = {
            docType: "authenticationEvent",
            eventId: normalizedEventId,
            did: normalizedDid,
            timestamp,
            decision: normalizedDecision,
            reason: normalizedReason,
            observedMacAddress:
                this._normalizeOptionalValue(observedMacAddress),
            observedIpAddress:
                this._normalizeOptionalValue(observedIpAddress),
            spoofingClassification:
                normalizedSpoofingClassification.trim().toUpperCase(),
            recordedBy: ctx.clientIdentity.getID(),
            transactionId
        };

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

        return JSON.stringify(event);
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
