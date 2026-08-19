"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const {
    TIMING_METRICS,
    calculateTimingStats,
    calculateSecurityMetrics,
    roundNumber
} = require("./statistics");

const CSV_COLUMNS = [
    "batchSize",
    "scenario",
    "iteration",
    "did",
    "expectedDecision",
    "actualDecision",
    "expectedClassification",
    "actualClassification",
    "challengeDurationMs",
    "signingDurationMs",
    "verificationDurationMs",
    "spoofingCheckDurationMs",
    "totalAuthenticationDurationMs",
    "httpStatus",
    "auditEventId",
    "auditConfirmed",
    "testPassed",
    "timestamp"
];

function csvEscape(value) {
    if (value === null || value === undefined) {
        return "";
    }

    const text = String(value);

    if (/[",\n\r]/.test(text)) {
        return `"${text.replace(/"/g, "\"\"")}"`;
    }

    return text;
}

function primaryAuditEventId(result) {
    if (result.auditEventId) {
        return result.auditEventId;
    }

    if (
        Array.isArray(result.auditEventIds) &&
        result.auditEventIds.length > 0
    ) {
        return result.auditEventIds.join(";");
    }

    return "";
}

function resultToCsvRow(result) {
    const row = {
        batchSize: result.batchSize,
        scenario: result.scenario,
        iteration: result.iteration,
        did: result.did,
        expectedDecision: result.expectedDecision,
        actualDecision: result.actualDecision,
        expectedClassification: result.expectedClassification,
        actualClassification: result.actualClassification,
        challengeDurationMs: result.challengeDurationMs,
        signingDurationMs: result.signingDurationMs,
        verificationDurationMs: result.verificationDurationMs,
        spoofingCheckDurationMs: result.spoofingCheckDurationMs,
        totalAuthenticationDurationMs: result.totalAuthenticationDurationMs,
        httpStatus: result.httpStatus,
        auditEventId: primaryAuditEventId(result),
        auditConfirmed: result.auditConfirmed,
        testPassed: result.testPassed,
        timestamp: result.timestamp
    };

    return CSV_COLUMNS.map((column) => csvEscape(row[column])).join(",");
}

function observationsToCsv(results) {
    return [
        CSV_COLUMNS.join(","),
        ...results.map(resultToCsvRow)
    ].join("\n") + "\n";
}

function statusText(passed) {
    return passed ? "PASS" : "FAIL";
}

function buildRequirementTable(summary) {
    const performance = summary.performance || {};
    const requirements = summary.requirements || {};

    return [
        "| Metric | Requirement | Measured Result | Status |",
        "| --- | --- | --- | --- |",
        `| Authentication response | <= 5000 ms average end-to-end | ${performance.averageTotalAuthenticationDurationMs ?? "n/a"} ms | ${statusText(requirements.authenticationUnder5Seconds)} |`,
        `| Spoofing comparison | <= 3000 ms average comparison time | ${performance.averageSpoofingCheckDurationMs ?? "n/a"} ms | ${statusText(requirements.spoofingDetectionUnder3Seconds)} |`
    ].join("\n");
}

function averageMetric(results, metric) {
    const stats = calculateTimingStats(results).overall[metric];

    return stats.mean;
}

function buildFinalSummary({
    timestamp,
    environment,
    batchSizes,
    results,
    batchSummaries,
    auditInvestigation,
    limitations
}) {
    const security = calculateSecurityMetrics(results);
    const performance = {};

    for (const metric of TIMING_METRICS) {
        const key = `average${metric[0].toUpperCase()}${metric.slice(1)}`;
        performance[key] = averageMetric(results, metric);
    }

    const authenticationAverage =
        performance.averageTotalAuthenticationDurationMs;
    const spoofingAverage =
        performance.averageSpoofingCheckDurationMs;
    const requirements = {
        authenticationUnder5Seconds:
            typeof authenticationAverage === "number" &&
            authenticationAverage <= 5000,
        spoofingDetectionUnder3Seconds:
            typeof spoofingAverage === "number" &&
            spoofingAverage <= 3000
    };

    return {
        evaluationDate: timestamp,
        environment,
        batchSizes,
        security: {
            spoofingDetectionRatePercent:
                security.spoofingDetectionRatePercent,
            falsePositiveRatePercent:
                security.falsePositiveRatePercent,
            falseNegativeRatePercent:
                security.falseNegativeRatePercent,
            authenticationSuccessRatePercent:
                security.authenticationSuccessRatePercent,
            replayRejectionRatePercent:
                security.replayRejectionRatePercent,
            invalidSignatureRejectionRatePercent:
                security.invalidSignatureRejectionRatePercent,
            suspendedDeviceRejectionRatePercent:
                security.suspendedDeviceRejectionRatePercent,
            revokedDeviceRejectionRatePercent:
                security.revokedDeviceRejectionRatePercent,
            counts: security.counts
        },
        performance,
        requirements,
        batchSummaries,
        auditInvestigation,
        formulas: {
            standardDeviation:
                "sample standard deviation over recorded non-null timing values",
            p95:
                "nearest-rank 95th percentile when at least two samples exist",
            truePositive:
                "spoofing attempt denied with the expected spoofing classification",
            falseNegative:
                "spoofing attempt not denied with the expected spoofing classification",
            falsePositive:
                "legitimate authentication not granted with classification NONE",
            trueNegative:
                "legitimate authentication granted with classification NONE"
        },
        requirementTableMarkdown: buildRequirementTable({
            performance,
            requirements
        }),
        limitations
    };
}

async function ensureResultsDirectory(resultsDir) {
    await fs.mkdir(resultsDir, {
        recursive: true
    });
}

async function writeJson(filePath, value) {
    await fs.writeFile(
        filePath,
        `${JSON.stringify(value, null, 2)}\n`,
        "utf8"
    );
}

async function writeBatchResult({
    resultsDir,
    batchSize,
    timestamp,
    report
}) {
    await ensureResultsDirectory(resultsDir);

    const filePath = path.join(
        resultsDir,
        `evaluation-${batchSize}-${timestamp}.json`
    );

    await writeJson(filePath, report);

    return filePath;
}

async function writeSummaryResults({
    resultsDir,
    timestamp,
    summary,
    observations
}) {
    await ensureResultsDirectory(resultsDir);

    const summaryPath = path.join(
        resultsDir,
        `evaluation-summary-${timestamp}.json`
    );
    const csvPath = path.join(
        resultsDir,
        `evaluation-observations-${timestamp}.csv`
    );

    await writeJson(summaryPath, summary);
    await fs.writeFile(csvPath, observationsToCsv(observations), "utf8");

    return {
        summaryPath,
        csvPath
    };
}

function compactBatchConsoleSummary(batchReport) {
    const legitimateStats =
        batchReport.summary.timing.byScenario.LEGITIMATE || {};
    const totalStats =
        legitimateStats.totalAuthenticationDurationMs || {};
    const security = batchReport.summary.security;

    return {
        batchSize: batchReport.batchSize,
        passed: batchReport.summary.passed,
        failed: batchReport.summary.failed,
        legitimateMeanTotalAuthenticationDurationMs:
            roundNumber(totalStats.mean),
        spoofingDetectionRatePercent:
            security.spoofingDetectionRatePercent,
        falsePositiveRatePercent:
            security.falsePositiveRatePercent,
        replayRejectionRatePercent:
            security.replayRejectionRatePercent,
        invalidSignatureRejectionRatePercent:
            security.invalidSignatureRejectionRatePercent,
        suspendedDeviceRejectionRatePercent:
            security.suspendedDeviceRejectionRatePercent,
        revokedDeviceRejectionRatePercent:
            security.revokedDeviceRejectionRatePercent
    };
}

module.exports = {
    CSV_COLUMNS,
    observationsToCsv,
    buildRequirementTable,
    buildFinalSummary,
    writeBatchResult,
    writeSummaryResults,
    compactBatchConsoleSummary
};
