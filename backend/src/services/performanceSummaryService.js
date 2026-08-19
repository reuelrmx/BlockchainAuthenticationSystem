"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const performanceConfig = require("../config/performanceConfig");
const {
    getLivePerformanceMetrics
} = require("./performanceMetricsService");

const CONCURRENCY_SUMMARY_PATTERN =
    /^concurrency-summary-\d{4}-\d{2}-\d{2}T.+\.json$/;

async function readJsonFile(filePath) {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function findLatestConcurrencySummary() {
    let entries;

    try {
        entries = await fs.readdir(performanceConfig.evaluationResultsDir, {
            withFileTypes: true
        });
    } catch (error) {
        if (error.code === "ENOENT") {
            return null;
        }

        throw error;
    }

    const candidates = [];

    for (const entry of entries) {
        if (
            !entry.isFile() ||
            !CONCURRENCY_SUMMARY_PATTERN.test(entry.name)
        ) {
            continue;
        }

        const filePath = path.join(
            performanceConfig.evaluationResultsDir,
            entry.name
        );
        const stat = await fs.stat(filePath);

        candidates.push({
            filePath,
            fileName: entry.name,
            mtimeMs: stat.mtimeMs
        });
    }

    candidates.sort((left, right) =>
        right.mtimeMs - left.mtimeMs ||
        right.fileName.localeCompare(left.fileName)
    );

    return candidates[0] || null;
}

function buildRequirementStatus(formalSummary) {
    if (!formalSummary) {
        return {
            authenticationUnder5Seconds: null,
            spoofingUnder3Seconds: null,
            fiftyConcurrent: null
        };
    }

    const results = formalSummary.results || {};
    const level50 = results["50"] || null;
    const spoofingMeans = Object.values(results)
        .map((result) => result.spoofingCheckDurationMs?.mean)
        .filter((value) => Number.isFinite(value));
    const maxSpoofingMean = spoofingMeans.length > 0
        ? Math.max(...spoofingMeans)
        : null;

    return {
        authenticationUnder5Seconds: level50
            ? Boolean(
                level50.meanLatencyMs <= 5000 &&
                level50.p95LatencyMs <= 5000
            )
            : null,
        spoofingUnder3Seconds: maxSpoofingMean === null
            ? null
            : maxSpoofingMean <= 3000,
        fiftyConcurrent:
            formalSummary.requirement50Concurrent?.passed ?? null
    };
}

async function getFormalConcurrencySummary() {
    const latest = await findLatestConcurrencySummary();

    if (!latest) {
        return {
            source: "FORMAL_EVALUATION_METRICS",
            available: false,
            message: "No evaluation data available"
        };
    }

    const summary = await readJsonFile(latest.filePath);

    return {
        source: "FORMAL_EVALUATION_METRICS",
        available: true,
        fileName: latest.fileName,
        evaluationDate: summary.evaluationDate,
        levels: summary.levels || [],
        roundsPerLevel: summary.roundsPerLevel || null,
        results: summary.results || {},
        baselineComparison: summary.baselineComparison || null,
        requirement50Concurrent:
            summary.requirement50Concurrent || null,
        requirementStatus: buildRequirementStatus(summary),
        limitations: summary.limitations || []
    };
}

async function buildPerformanceSummary() {
    const formal = await getFormalConcurrencySummary();

    return {
        live: getLivePerformanceMetrics(),
        formal
    };
}

module.exports = {
    buildPerformanceSummary,
    getFormalConcurrencySummary
};
