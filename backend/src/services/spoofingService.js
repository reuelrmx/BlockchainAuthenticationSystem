"use strict";

const { performance } = require("node:perf_hooks");

const spoofingConfig = require("../config/spoofingConfig");

const {
    hashMacAddress,
    isIpInCidr,
    normalizeAllowedIpCidr,
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

function evaluateMacContext(device, observedMacAddress) {
    const observed = normalizeMacAddress(observedMacAddress);

    if (device?.registeredMacAddressHash) {
        const observedHash = hashMacAddress(observed);

        return {
            match: observedHash
                ? observedHash === device.registeredMacAddressHash
                : null,
            registered: device.registeredMacAddressHash,
            observed,
            observedHash
        };
    }

    return evaluateMatch(
        device?.registeredMacAddress,
        observed,
        normalizeMacAddress
    );
}

function evaluateIpContext(device, observedIpAddress) {
    const observed = normalizeIpAddress(observedIpAddress);
    const allowedCidr = normalizeAllowedIpCidr(
        device?.allowedIpCidr ||
        device?.registeredIpAddress
    );

    if (allowedCidr) {
        return {
            match: isIpInCidr(observed, allowedCidr),
            registered: allowedCidr,
            observed
        };
    }

    return evaluateMatch(
        device?.registeredIpAddress,
        observed,
        normalizeIpAddress
    );
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
    const macEvaluation = evaluateMacContext(
        device,
        observedContext?.observedMacAddress
    );
    const ipEvaluation = evaluateIpContext(
        device,
        observedContext?.observedIpAddress
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
        registeredMacAddressHash:
            device?.registeredMacAddressHash || null,
        registeredIpAddress: ipEvaluation.registered,
        allowedIpCidr: ipEvaluation.registered,
        observedMacAddress: macEvaluation.observed,
        observedMacAddressHash: macEvaluation.observedHash || null,
        observedIpAddress: ipEvaluation.observed,
        comparisonTimeMs: Number(
            (performance.now() - start).toFixed(3)
        )
    };
}

module.exports = {
    evaluateSpoofing
};
