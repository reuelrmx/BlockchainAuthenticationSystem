"use strict";

const performanceConfig = require("../config/performanceConfig");

const processStartedAt = new Date();
const recentAttempts = [];
const counters = {
    total: 0,
    granted: 0,
    denied: 0,
    timeout: 0
};
let lastAuthenticationAt = null;

function roundNumber(value, digits = 3) {
    if (!Number.isFinite(value)) {
        return null;
    }

    return Number(value.toFixed(digits));
}

function calculateStats(values) {
    const numbers = values
        .filter((value) => Number.isFinite(value))
        .sort((left, right) => left - right);
    const count = numbers.length;

    if (count === 0) {
        return {
            count: 0,
            mean: null,
            median: null,
            p95: null
        };
    }

    const sum = numbers.reduce((total, value) => total + value, 0);
    const middle = Math.floor(count / 2);
    const median = count % 2 === 0
        ? (numbers[middle - 1] + numbers[middle]) / 2
        : numbers[middle];
    const p95Index = count >= 2
        ? Math.ceil(0.95 * count) - 1
        : null;

    return {
        count,
        mean: roundNumber(sum / count),
        median: roundNumber(median),
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

function recordAuthenticationAttempt({
    decision,
    authenticated,
    httpStatus,
    totalAuthenticationDurationMs,
    spoofingCheckDurationMs,
    timeout = false
}) {
    const timestamp = new Date();
    const normalizedDecision = String(decision || "DENIED").toUpperCase();
    const granted = authenticated === true ||
        normalizedDecision === "GRANTED";

    counters.total += 1;

    if (granted) {
        counters.granted += 1;
    } else {
        counters.denied += 1;
    }

    if (timeout) {
        counters.timeout += 1;
    }

    lastAuthenticationAt = timestamp;
    recentAttempts.push({
        timestamp: timestamp.toISOString(),
        timestampMs: timestamp.getTime(),
        decision: normalizedDecision,
        authenticated: granted,
        httpStatus,
        totalAuthenticationDurationMs,
        spoofingCheckDurationMs,
        timeout
    });

    while (recentAttempts.length > performanceConfig.recentSampleLimit) {
        recentAttempts.shift();
    }
}

function getLivePerformanceMetrics(now = new Date()) {
    const latencyStats = calculateStats(
        recentAttempts.map((attempt) =>
            attempt.totalAuthenticationDurationMs
        )
    );
    const spoofingStats = calculateStats(
        recentAttempts.map((attempt) => attempt.spoofingCheckDurationMs)
    );
    const windowStartMs = now.getTime() -
        (performanceConfig.recentThroughputWindowSeconds * 1000);
    const recentWindowAttempts = recentAttempts.filter((attempt) =>
        attempt.timestampMs >= windowStartMs
    );
    const processLifetimeSeconds =
        (now.getTime() - processStartedAt.getTime()) / 1000;

    return {
        source: "LIVE_OPERATIONAL_METRICS",
        persistence: "process-lifetime in-memory metrics; reset on backend restart",
        processStartedAt: processStartedAt.toISOString(),
        lastAuthenticationAt: lastAuthenticationAt
            ? lastAuthenticationAt.toISOString()
            : null,
        totalAttemptsSinceStart: counters.total,
        grantedSinceStart: counters.granted,
        deniedSinceStart: counters.denied,
        timeoutSinceStart: counters.timeout,
        successRatePercent: percent(counters.granted, counters.total),
        failureRatePercent: percent(counters.denied, counters.total),
        timeoutRatePercent: percent(counters.timeout, counters.total),
        recentSampleCount: recentAttempts.length,
        meanRecentAuthenticationLatencyMs: latencyStats.mean,
        medianRecentAuthenticationLatencyMs: latencyStats.median,
        p95RecentAuthenticationLatencyMs: latencyStats.p95,
        meanRecentSpoofingCheckDurationMs: spoofingStats.mean,
        recentThroughputWindowSeconds:
            performanceConfig.recentThroughputWindowSeconds,
        recentThroughputPerSecond: roundNumber(
            recentWindowAttempts.length /
            performanceConfig.recentThroughputWindowSeconds
        ),
        lifetimeThroughputPerSecond: processLifetimeSeconds > 0
            ? roundNumber(counters.total / processLifetimeSeconds)
            : null
    };
}

module.exports = {
    getLivePerformanceMetrics,
    recordAuthenticationAttempt
};
