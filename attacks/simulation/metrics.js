"use strict";

const {
    LEGITIMATE_SCENARIOS,
    SPOOFING_SCENARIOS
} = require("./scenarios");

function roundMetric(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        return null;
    }

    return Number(value.toFixed(3));
}

function average(values) {
    const numericValues = values.filter(
        (value) => typeof value === "number" && Number.isFinite(value)
    );

    if (numericValues.length === 0) {
        return null;
    }

    const total = numericValues.reduce((sum, value) => sum + value, 0);

    return roundMetric(total / numericValues.length);
}

function calculateDetectionMetrics(results) {
    const completedResults = results.filter((result) => !result.skipped);
    const spoofingResults = completedResults.filter((result) =>
        SPOOFING_SCENARIOS.has(result.scenario)
    );
    const legitimateResults = completedResults.filter((result) =>
        LEGITIMATE_SCENARIOS.has(result.scenario)
    );

    const truePositives = spoofingResults.filter((result) =>
        result.actualDecision === "DENIED" &&
        result.actualSpoofingClassification ===
            result.expectedSpoofingClassification
    ).length;
    const falseNegatives = spoofingResults.length - truePositives;

    const falsePositives = legitimateResults.filter((result) =>
        result.actualDecision !== "GRANTED" ||
        result.actualSpoofingClassification !== "NONE"
    ).length;

    const detectionDenominator = truePositives + falseNegatives;
    const falsePositiveDenominator = legitimateResults.length;

    return {
        truePositives,
        falseNegatives,
        falsePositives,
        spoofingScenarioTests: spoofingResults.length,
        legitimateScenarioTests: legitimateResults.length,
        detectionAccuracyPercent: detectionDenominator === 0
            ? null
            : roundMetric((truePositives / detectionDenominator) * 100),
        falsePositiveRatePercent: falsePositiveDenominator === 0
            ? null
            : roundMetric(
                (falsePositives / falsePositiveDenominator) * 100
            )
    };
}

function summarizeResults(results) {
    const completedResults = results.filter((result) => !result.skipped);
    const passed = completedResults.filter(
        (result) => result.testPassed
    ).length;
    const failed = completedResults.length - passed;
    const detection = calculateDetectionMetrics(results);

    return {
        totalTests: completedResults.length,
        skipped: results.length - completedResults.length,
        passed,
        failed,
        detectionAccuracyPercent: detection.detectionAccuracyPercent,
        falsePositiveRatePercent: detection.falsePositiveRatePercent,
        averageAuthenticationLatencyMs: average(
            completedResults.map(
                (result) =>
                    result.totalEndToEndAuthenticationDurationMs
            )
        ),
        averageSpoofingCheckMs: average(
            completedResults.map(
                (result) => result.spoofingCheckDurationMs
            )
        ),
        truePositives: detection.truePositives,
        falseNegatives: detection.falseNegatives,
        falsePositives: detection.falsePositives,
        spoofingScenarioTests: detection.spoofingScenarioTests,
        legitimateScenarioTests: detection.legitimateScenarioTests
    };
}

module.exports = {
    summarizeResults
};
