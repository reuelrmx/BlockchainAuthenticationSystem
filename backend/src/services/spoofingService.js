"use strict";

const { performance } = require("node:perf_hooks");

const spoofingConfig = require("../config/spoofingConfig");

const {
    normalizeIpAddress,
    normalizeMacAddress
} = require("./networkContextService");

function evaluateMatch(registeredValue, observedValue, normalizer) {
    const registered = normalizer(registeredValue);
    const observed = normalizer(observedValue);

    if (!registered || !observed) {
        return {
            match: null,
            registered,
            observed
        };
    }

    return {
        match: registered === observed,
        registered,
        observed
    };
}

function classify(macMatch, ipMatch) {
    if (macMatch === false && ipMatch === false) {
        return "MAC_AND_IP_MISMATCH";
    }

    if (macMatch === false) {
        return "MAC_MISMATCH";
    }

    if (ipMatch === false) {
        return "IP_MISMATCH";
    }

    if (macMatch === null || ipMatch === null) {
        return "CONTEXT_INCOMPLETE";
    }

    return "NONE";
}

function evaluateSpoofing(device, observedContext) {
    const start = performance.now();
    const macEvaluation = evaluateMatch(
        device?.registeredMacAddress,
        observedContext?.observedMacAddress,
        normalizeMacAddress
    );
    const ipEvaluation = evaluateMatch(
        device?.registeredIpAddress,
        observedContext?.observedIpAddress,
        normalizeIpAddress
    );

    const classification = classify(
        macEvaluation.match,
        ipEvaluation.match
    );

    const detected =
        classification === "MAC_MISMATCH" ||
        classification === "IP_MISMATCH" ||
        classification === "MAC_AND_IP_MISMATCH";

    const deniedForIncompleteContext =
        classification === "CONTEXT_INCOMPLETE" &&
        spoofingConfig.denyIncompleteNetworkContext;

    return {
        detected,
        deniedForIncompleteContext,
        classification,
        macMatch: macEvaluation.match,
        ipMatch: ipEvaluation.match,
        registeredMacAddress: macEvaluation.registered,
        registeredIpAddress: ipEvaluation.registered,
        observedMacAddress: macEvaluation.observed,
        observedIpAddress: ipEvaluation.observed,
        comparisonTimeMs: Number(
            (performance.now() - start).toFixed(3)
        )
    };
}

module.exports = {
    evaluateSpoofing
};
