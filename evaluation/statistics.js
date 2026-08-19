"use strict";

const TIMING_METRICS = [
    "challengeDurationMs",
    "signingDurationMs",
    "verificationDurationMs",
    "spoofingCheckDurationMs",
    "totalAuthenticationDurationMs"
];

const SPOOFING_SCENARIOS = new Set([
    "MAC_SPOOF",
    "IP_SPOOF",
    "MAC_IP_SPOOF"
]);

const SPOOFING_CLASSIFICATIONS = new Set([
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH"
]);

function roundNumber(value, digits = 3) {
    if (!Number.isFinite(value)) {
        return null;
    }

    return Number(value.toFixed(digits));
}

function finiteNumbers(values) {
    return values.filter((value) => Number.isFinite(value));
}

function calculateStats(values) {
    const numbers = finiteNumbers(values).sort((a, b) => a - b);
    const count = numbers.length;

    if (count === 0) {
        return {
            count: 0,
            min: null,
            max: null,
            mean: null,
            median: null,
            standardDeviation: null,
            p95: null
        };
    }

    const sum = numbers.reduce((total, value) => total + value, 0);
    const mean = sum / count;
    const middle = Math.floor(count / 2);
    const median = count % 2 === 0
        ? (numbers[middle - 1] + numbers[middle]) / 2
        : numbers[middle];
    const variance = count > 1
        ? numbers.reduce(
            (total, value) => total + ((value - mean) ** 2),
            0
        ) / (count - 1)
        : 0;
    const p95Index = count >= 2
        ? Math.ceil(0.95 * count) - 1
        : null;

    return {
        count,
        min: roundNumber(numbers[0]),
        max: roundNumber(numbers[count - 1]),
        mean: roundNumber(mean),
        median: roundNumber(median),
        standardDeviation: roundNumber(Math.sqrt(variance)),
        p95: p95Index === null
            ? null
            : roundNumber(numbers[Math.min(p95Index, count - 1)])
    };
}

function percent(numerator, denominator) {
    if (!denominator) {
        return null;
    }

    return roundNumber((numerator / denominator) * 100, 2);
}

function groupByScenario(results) {
    return results.reduce((groups, result) => {
        if (!groups[result.scenario]) {
            groups[result.scenario] = [];
        }

        groups[result.scenario].push(result);

        return groups;
    }, {});
}

function calculateTimingStats(results) {
    const completed = results.filter((result) => !result.skipped);
    const byScenario = {};
    const scenarioGroups = groupByScenario(completed);

    for (const [scenario, scenarioResults] of Object.entries(
        scenarioGroups
    )) {
        byScenario[scenario] = {};

        for (const metric of TIMING_METRICS) {
            byScenario[scenario][metric] = calculateStats(
                scenarioResults.map((result) => result[metric])
            );
        }
    }

    const overall = {};

    for (const metric of TIMING_METRICS) {
        overall[metric] = calculateStats(
            completed.map((result) => result[metric])
        );
    }

    return {
        overall,
        byScenario
    };
}

function spoofingDetected(result) {
    return (
        result.actualDecision === "DENIED" &&
        SPOOFING_CLASSIFICATIONS.has(result.actualClassification)
    );
}

function isRejected(result, expectedStatus) {
    return (
        result.actualDecision === "DENIED" &&
        (
            typeof expectedStatus !== "number" ||
            result.httpStatus === expectedStatus
        )
    );
}

function calculateSecurityMetrics(results) {
    const completed = results.filter((result) => !result.skipped);
    const legitimate = completed.filter((result) =>
        result.scenario === "LEGITIMATE"
    );
    const spoofing = completed.filter((result) =>
        SPOOFING_SCENARIOS.has(result.scenario)
    );
    const replay = completed.filter((result) =>
        result.scenario === "REPLAY"
    );
    const invalidSignature = completed.filter((result) =>
        result.scenario === "INVALID_SIGNATURE"
    );
    const suspended = completed.filter((result) =>
        result.scenario === "SUSPENDED"
    );
    const revoked = completed.filter((result) =>
        result.scenario === "REVOKED"
    );

    const truePositives = spoofing.filter((result) =>
        spoofingDetected(result) &&
        result.actualClassification === result.expectedClassification
    ).length;
    const falseNegatives = spoofing.length - truePositives;
    const trueNegatives = legitimate.filter((result) =>
        result.actualDecision === "GRANTED" &&
        result.actualClassification === "NONE"
    ).length;
    const falsePositives = legitimate.length - trueNegatives;

    const successfulLegitimate = legitimate.filter((result) =>
        result.actualDecision === "GRANTED" &&
        result.httpStatus === 200
    ).length;
    const rejectedReplays = replay.filter((result) =>
        isRejected(result, 401)
    ).length;
    const rejectedInvalidSignatures = invalidSignature.filter((result) =>
        isRejected(result, 401)
    ).length;
    const rejectedSuspended = suspended.filter((result) =>
        isRejected(result, 403)
    ).length;
    const rejectedRevoked = revoked.filter((result) =>
        isRejected(result, 403)
    ).length;

    return {
        counts: {
            truePositives,
            falseNegatives,
            falsePositives,
            trueNegatives,
            legitimateAttempts: legitimate.length,
            spoofingAttempts: spoofing.length,
            replayAttempts: replay.length,
            invalidSignatureAttempts: invalidSignature.length,
            suspendedAttempts: suspended.length,
            revokedAttempts: revoked.length
        },
        spoofingDetectionRatePercent: percent(
            truePositives,
            truePositives + falseNegatives
        ),
        falsePositiveRatePercent: percent(
            falsePositives,
            falsePositives + trueNegatives
        ),
        falseNegativeRatePercent: percent(
            falseNegatives,
            truePositives + falseNegatives
        ),
        authenticationSuccessRatePercent: percent(
            successfulLegitimate,
            legitimate.length
        ),
        replayRejectionRatePercent: percent(
            rejectedReplays,
            replay.length
        ),
        invalidSignatureRejectionRatePercent: percent(
            rejectedInvalidSignatures,
            invalidSignature.length
        ),
        suspendedDeviceRejectionRatePercent: percent(
            rejectedSuspended,
            suspended.length
        ),
        revokedDeviceRejectionRatePercent: percent(
            rejectedRevoked,
            revoked.length
        )
    };
}

function summarizeResults(results) {
    const completed = results.filter((result) => !result.skipped);
    const passed = completed.filter((result) => result.testPassed).length;
    const failed = completed.length - passed;

    return {
        total: results.length,
        completed: completed.length,
        skipped: results.length - completed.length,
        passed,
        failed,
        passRatePercent: percent(passed, completed.length),
        timing: calculateTimingStats(results),
        security: calculateSecurityMetrics(results)
    };
}

module.exports = {
    TIMING_METRICS,
    calculateStats,
    calculateTimingStats,
    calculateSecurityMetrics,
    summarizeResults,
    percent,
    roundNumber
};
