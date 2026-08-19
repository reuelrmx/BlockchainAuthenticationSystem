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
        fabricConfig.accessControlContractName,
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

async function getAuthenticationEvent(eventId) {
    return evaluateTransactionForContract(
        fabricConfig.accessControlContractName,
        "GetAuthenticationEvent",
        eventId
    );
}

async function getAllAuthenticationEvents() {
    return evaluateTransactionForContract(
        fabricConfig.accessControlContractName,
        "GetAllAuthenticationEvents"
    );
}

async function getAuthenticationEventsByDevice(did) {
    return evaluateTransactionForContract(
        fabricConfig.accessControlContractName,
        "GetAuthenticationEventsByDevice",
        did
    );
}

module.exports = {
    DEFAULT_SPOOFING_CLASSIFICATION,
    recordAuthenticationEvent,
    getAuthenticationEvent,
    getAllAuthenticationEvents,
    getAuthenticationEventsByDevice
};
