"use strict";

const path = require("node:path");

const backendRoot = path.resolve(__dirname, "../..");
const repoRoot = path.resolve(backendRoot, "..");

function parsePositiveInteger(value, defaultValue) {
    if (value === undefined || value === null || value === "") {
        return defaultValue;
    }

    const parsed = Number(value);

    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        return defaultValue;
    }

    return parsed;
}

function resolveFromRepoRoot(value, fallback) {
    const target = value || fallback;

    if (path.isAbsolute(target)) {
        return target;
    }

    return path.resolve(repoRoot, target);
}

module.exports = {
    evaluationResultsDir: resolveFromRepoRoot(
        process.env.PERFORMANCE_RESULTS_DIR,
        "evaluation/results"
    ),
    recentSampleLimit: parsePositiveInteger(
        process.env.PERFORMANCE_RECENT_SAMPLE_LIMIT,
        250
    ),
    recentThroughputWindowSeconds: parsePositiveInteger(
        process.env.PERFORMANCE_RECENT_THROUGHPUT_WINDOW_SECONDS,
        60
    )
};
