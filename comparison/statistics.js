"use strict";

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
    const numbers = finiteNumbers(values).sort((left, right) => left - right);
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
        ? numbers.reduce((total, value) => total + ((value - mean) ** 2), 0) /
            (count - 1)
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

function summarizeObservations(observations) {
    const measured = observations.filter((observation) =>
        observation.measured === true
    );
    const successful = measured.filter((observation) =>
        observation.success === true
    );
    const failed = measured.filter((observation) =>
        observation.success === false
    );
    const timeouts = measured.filter((observation) =>
        observation.timeout === true
    );
    const latencyStats = calculateStats(
        measured.map((observation) => observation.latencyMs)
    );

    return {
        totalObservations: observations.length,
        measuredObservations: measured.length,
        notRunObservations: observations.length - measured.length,
        successfulAuthentications: successful.length,
        failedAuthentications: failed.length,
        successRatePercent: percent(successful.length, measured.length),
        failureRatePercent: percent(failed.length, measured.length),
        timeoutCount: timeouts.length,
        timeoutRatePercent: percent(timeouts.length, measured.length),
        latencyMs: latencyStats
    };
}

module.exports = {
    calculateStats,
    percent,
    roundNumber,
    summarizeObservations
};
