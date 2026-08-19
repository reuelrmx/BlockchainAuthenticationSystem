"use strict";

const crypto = require("node:crypto");

const fabricConfig = require("../config/fabricConfig");

const {
    submitTransactionForContract,
    evaluateTransactionForContract
} = require("./fabricService");

const DEFAULT_SPOOFING_CLASSIFICATION = "NOT_EVALUATED";

function normalizeOptionalValue(value) {
    if (typeof value !== "string" || value.trim() === "") {
        return "";
    }

    return value.trim();
}

async function recordAuthenticationEvent({
    eventId = crypto.randomUUID(),
    did,
    decision,
    reason,
    observedMacAddress,
    observedIpAddress,
    spoofingClassification = DEFAULT_SPOOFING_CLASSIFICATION
}) {
    return submitTransactionForContract(
        fabricConfig.auditLogContractName,
        "LogAuthenticationEvent",
        eventId,
        did,
        decision,
        reason,
        normalizeOptionalValue(observedMacAddress),
        normalizeOptionalValue(observedIpAddress),
        spoofingClassification
    );
}

async function verifyAuthentication({
    eventId = crypto.randomUUID(),
    did,
    challengePayload,
    signatureBase64,
    observedMacAddress,
    observedIpAddress,
    spoofingClassification = DEFAULT_SPOOFING_CLASSIFICATION,
    denyIncompleteNetworkContext = false
}) {
    return submitTransactionForContract(
        fabricConfig.accessControlContractName,
        "VerifyAuthentication",
        eventId,
        did,
        challengePayload,
        signatureBase64,
        normalizeOptionalValue(observedMacAddress),
        normalizeOptionalValue(observedIpAddress),
        spoofingClassification,
        String(Boolean(denyIncompleteNetworkContext))
    );
}

async function getAuthenticationEvent(eventId) {
    return evaluateTransactionForContract(
        fabricConfig.auditLogContractName,
        "GetAuthenticationEvent",
        eventId
    );
}

async function getAllAuthenticationEvents() {
    return evaluateTransactionForContract(
        fabricConfig.auditLogContractName,
        "GetAllAuthenticationEvents"
    );
}

async function getAuthenticationEventsByDevice(did) {
    return evaluateTransactionForContract(
        fabricConfig.auditLogContractName,
        "GetEventsByDevice",
        did
    );
}

module.exports = {
    DEFAULT_SPOOFING_CLASSIFICATION,
    recordAuthenticationEvent,
    verifyAuthentication,
    getAuthenticationEvent,
    getAllAuthenticationEvents,
    getAuthenticationEventsByDevice
};
