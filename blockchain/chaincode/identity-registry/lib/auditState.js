"use strict";

const crypto = require("node:crypto");

const DEFAULT_SPOOFING_CLASSIFICATION = "NOT_EVALUATED";

function requireValue(value, fieldName) {
    if (typeof value !== "string" || value.trim() === "") {
        throw new Error(`${fieldName} is required`);
    }
}

function getTransactionTimestamp(ctx) {
    const timestamp = ctx.stub.getTxTimestamp();
    const seconds =
        typeof timestamp.seconds === "object"
            ? timestamp.seconds.toNumber()
            : Number(timestamp.seconds);
    const milliseconds =
        seconds * 1000 + Math.floor(timestamp.nanos / 1000000);

    return new Date(milliseconds).toISOString();
}

function normalizeOptionalValue(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return null;
    }

    return value.trim();
}

function normalizeMacAddress(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return null;
    }

    const compact = value
        .trim()
        .replace(/[-:.]/g, "")
        .toUpperCase();

    if (!/^[0-9A-F]{12}$/.test(compact)) {
        return null;
    }

    return compact.match(/.{2}/g).join(":");
}

function hashMacAddress(value) {
    const normalized = normalizeMacAddress(value);

    if (!normalized) {
        return null;
    }

    return crypto
        .createHash("sha256")
        .update(normalized)
        .digest("hex");
}

function createAuthenticationEventKey(ctx, eventId) {
    return ctx.stub.createCompositeKey("AUTH_EVENT", [eventId]);
}

function createAuthenticationEventByDeviceKey(ctx, did, eventId) {
    return ctx.stub.createCompositeKey(
        "AUTH_EVENT_BY_DEVICE",
        [did, eventId]
    );
}

function createAuditEventKey(ctx, eventId) {
    return ctx.stub.createCompositeKey("AUDIT_EVENT", [eventId]);
}

function createAuditEventByDeviceKey(ctx, did, eventId) {
    return ctx.stub.createCompositeKey(
        "AUDIT_EVENT_BY_DEVICE",
        [did, eventId]
    );
}

async function eventExists(ctx, key) {
    const bytes = await ctx.stub.getState(key);

    return Boolean(bytes && bytes.length > 0);
}

async function authenticationEventExists(ctx, eventId) {
    return eventExists(
        ctx,
        createAuthenticationEventKey(ctx, eventId)
    );
}

function buildAuthenticationEvent({
    ctx,
    eventId,
    did,
    decision,
    reason,
    observedMacAddress,
    observedIpAddress,
    spoofingClassification = DEFAULT_SPOOFING_CLASSIFICATION
}) {
    const observedMacAddressHash = hashMacAddress(observedMacAddress);

    return {
        docType: "authenticationEvent",
        eventId,
        did,
        timestamp: getTransactionTimestamp(ctx),
        decision,
        reason,
        observedMacAddressHash,
        observedIpAddress: normalizeOptionalValue(observedIpAddress),
        spoofingClassification,
        recordedBy: ctx.clientIdentity.getID(),
        transactionId: ctx.stub.getTxID()
    };
}

async function putAuthenticationEvent(ctx, event) {
    const eventKey = createAuthenticationEventKey(ctx, event.eventId);
    const deviceEventKey = createAuthenticationEventByDeviceKey(
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

async function putGenericAuditEvent(ctx, event) {
    const eventKey = createAuditEventKey(ctx, event.eventId);

    if (await eventExists(ctx, eventKey)) {
        throw new Error(`Audit event ${event.eventId} already exists`);
    }

    await ctx.stub.putState(
        eventKey,
        Buffer.from(JSON.stringify(event))
    );

    if (event.did) {
        await ctx.stub.putState(
            createAuditEventByDeviceKey(ctx, event.did, event.eventId),
            Buffer.from(JSON.stringify({
                eventId: event.eventId
            }))
        );
    }

    ctx.stub.setEvent(
        "AuditEventRecorded",
        Buffer.from(JSON.stringify({
            eventId: event.eventId,
            eventType: event.eventType,
            did: event.did || null,
            timestamp: event.timestamp,
            transactionId: event.transactionId
        }))
    );
}

async function getAuthenticationEvent(ctx, eventId) {
    const key = createAuthenticationEventKey(ctx, eventId.trim());
    const bytes = await ctx.stub.getState(key);

    if (!bytes || bytes.length === 0) {
        throw new Error(
            `Authentication event ${eventId} does not exist`
        );
    }

    return bytes.toString();
}

async function getAllAuthenticationEvents(ctx) {
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

async function getAuthenticationEventsByDevice(ctx, did) {
    const iterator = await ctx.stub.getStateByPartialCompositeKey(
        "AUTH_EVENT_BY_DEVICE",
        [did]
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
                    const eventJson = await getAuthenticationEvent(
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

function buildGenericAuditEvent(ctx, eventType, fields = {}) {
    return {
        docType: "auditEvent",
        eventId: fields.eventId,
        eventType,
        did: fields.did || null,
        timestamp: getTransactionTimestamp(ctx),
        details: fields.details || {},
        recordedBy: ctx.clientIdentity.getID(),
        transactionId: ctx.stub.getTxID()
    };
}

module.exports = {
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
};
