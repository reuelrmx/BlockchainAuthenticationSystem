"use strict";

const fabricConfig = require("../config/fabricConfig");
const {
    evaluateTransactionForContract,
    submitAdminTransactionForContract
} = require("./fabricService");

const DEFAULT_ACCESS_POLICY = {
    requireMacContext: true,
    requireIpContext: true,
    denyIncompleteNetworkContext: false,
    macMismatchAction: "DENY",
    ipMismatchAction: "DENY"
};

function normalizeAction(value, fieldName) {
    const normalized = String(value || "").trim().toUpperCase();

    if (normalized === "DENY" || normalized === "ALLOW") {
        return normalized;
    }

    const error = new Error(`${fieldName} must be DENY or ALLOW`);
    error.statusCode = 400;
    throw error;
}

function normalizeBoolean(value) {
    return value === true || value === "true" || value === 1;
}

function normalizePolicy(input) {
    const supplied = input && typeof input === "object" ? input : {};

    return {
        requireMacContext: normalizeBoolean(
            supplied.requireMacContext ??
            DEFAULT_ACCESS_POLICY.requireMacContext
        ),
        requireIpContext: normalizeBoolean(
            supplied.requireIpContext ??
            DEFAULT_ACCESS_POLICY.requireIpContext
        ),
        denyIncompleteNetworkContext: normalizeBoolean(
            supplied.denyIncompleteNetworkContext ??
            DEFAULT_ACCESS_POLICY.denyIncompleteNetworkContext
        ),
        macMismatchAction: normalizeAction(
            supplied.macMismatchAction ??
            DEFAULT_ACCESS_POLICY.macMismatchAction,
            "MAC mismatch action"
        ),
        ipMismatchAction: normalizeAction(
            supplied.ipMismatchAction ??
            DEFAULT_ACCESS_POLICY.ipMismatchAction,
            "IP mismatch action"
        )
    };
}

async function getAccessPolicy() {
    return evaluateTransactionForContract(
        fabricConfig.accessControlContractName,
        "GetAccessPolicy"
    );
}

async function updateAccessPolicy(policy) {
    const normalizedPolicy = normalizePolicy(policy);

    return submitAdminTransactionForContract(
        fabricConfig.accessControlContractName,
        "UpdateAccessPolicy",
        JSON.stringify(normalizedPolicy)
    );
}

module.exports = {
    DEFAULT_ACCESS_POLICY,
    getAccessPolicy,
    normalizePolicy,
    updateAccessPolicy
};
