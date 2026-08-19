#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const CSV_COLUMNS = [
    "timestamp",
    "system",
    "scenario",
    "batchSize",
    "concurrencyLevel",
    "round",
    "iteration",
    "measured",
    "result",
    "success",
    "timeout",
    "latencyMs",
    "expected",
    "expectedMet",
    "notes"
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

function observationToCsvRow(observation) {
    return CSV_COLUMNS.map((column) =>
        csvEscape(observation[column])
    ).join(",");
}

function observationsToCsv(observations) {
    return [
        CSV_COLUMNS.join(","),
        ...observations.map(observationToCsvRow)
    ].join("\n") + "\n";
}

function formatValue(value, suffix = "") {
    if (value === null || value === undefined) {
        return "n/a";
    }

    return `${value}${suffix}`;
}

function resultCell(protocol, scenario) {
    return protocol.securityScenarios?.[scenario] || "NOT_RUN";
}

function buildSecurityScenarioTable(summary) {
    const radius = summary.radius || {};
    const ldap = summary.ldap || {};
    const fabric = summary.fabric || {};
    const scenarios = [
        "legitimateAuthentication",
        "invalidCredentialOrProof",
        "repeatedStaticCredential",
        "capturedSignedResponseReplay",
        "macContextMismatch",
        "ipContextMismatch",
        "revokedOrDisabledIdentity",
        "centralServerOutage",
        "auditEvidence"
    ];

    return [
        "| Scenario | Blockchain Result | RADIUS Result | LDAP Result | Interpretation |",
        "| --- | --- | --- | --- | --- |",
        ...scenarios.map((scenario) => [
            scenario,
            resultCell(fabric, scenario),
            resultCell(radius, scenario),
            resultCell(ldap, scenario),
            summary.interpretations?.[scenario] || ""
        ].map((value) => String(value).replace(/\|/g, "\\|")).join(" | "))
            .map((row) => `| ${row} |`)
    ].join("\n");
}

function buildSpoofingResistanceMatrix(summary) {
    const matrix = summary.spoofingResistanceMatrix || {};
    const rows = [
        "cryptographicDeviceProof",
        "serverGeneratedNonce",
        "capturedResponseReplayResistance",
        "staticCredentialReuse",
        "macContextEnforcement",
        "ipContextEnforcement",
        "identityDisableRevocation",
        "centralDecisionPoint",
        "immutableAuditTrail",
        "faultTolerance"
    ];

    return [
        "| Capability | Blockchain/Fabric | RADIUS | LDAP | Basis |",
        "| --- | --- | --- | --- | --- |",
        ...rows.map((row) => {
            const entry = matrix[row] || {};

            return [
                row,
                entry.fabric || "n/a",
                entry.radius || "n/a",
                entry.ldap || "n/a",
                entry.basis || ""
            ].map((value) => String(value).replace(/\|/g, "\\|")).join(" | ");
        }).map((row) => `| ${row} |`)
    ].join("\n");
}

function buildConcurrencyTable(summary) {
    const levels = ["1", "10", "25", "50"];
    const rows = [
        ["Fabric", summary.fabric?.concurrency50Result
            ? { "50": summary.fabric.concurrency50Result }
            : {}],
        ["RADIUS", summary.radius?.concurrency?.levels || {}],
        ["LDAP", summary.ldap?.concurrency?.levels || {}]
    ];

    return [
        "| System | Level | Success Rate | Timeout Rate | Mean | Median | P95 | Throughput |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ...rows.flatMap(([system, results]) =>
            levels
                .filter((level) => results[level])
                .map((level) => {
                    const result = results[level];
                    const latency = result.latencyMs || {};

                    return [
                        system,
                        level,
                        formatValue(result.successRatePercent, "%"),
                        formatValue(result.timeoutRatePercent, "%"),
                        formatValue(result.meanLatencyMs ?? latency.mean, " ms"),
                        formatValue(result.medianLatencyMs ?? latency.median, " ms"),
                        formatValue(result.p95LatencyMs ?? latency.p95, " ms"),
                        formatValue(result.throughputPerSecond, " auth/s")
                    ].join(" | ");
                })
        ).map((row) => `| ${row} |`)
    ].join("\n");
}

function buildLatencyTable(summary) {
    const rows = [
        ["Fabric", summary.fabric?.latency],
        ["RADIUS", summary.radius?.latency],
        ["LDAP", summary.ldap?.latency]
    ];

    return [
        "| System | Count | Mean | Median | Stddev | P95 | Success Rate | Throughput |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ...rows.map(([name, latency]) => {
            const stats = latency?.latencyMs || {};

            return [
                name,
                formatValue(stats.count),
                formatValue(stats.mean, " ms"),
                formatValue(stats.median, " ms"),
                formatValue(stats.standardDeviation, " ms"),
                formatValue(stats.p95, " ms"),
                formatValue(latency?.successRatePercent, "%"),
                formatValue(latency?.throughputPerSecond, " auth/s")
            ].join(" | ");
        }).map((row) => `| ${row} |`)
    ].join("\n");
}

function buildMarkdownReport(summary) {
    return [
        "# Traditional Authentication Comparison",
        "",
        `Generated: ${summary.generatedAt}`,
        "",
        "## Tool Availability",
        "",
        "```json",
        JSON.stringify(summary.toolAvailability, null, 2),
        "```",
        "",
        "## Latency Summary",
        "",
        buildLatencyTable(summary),
        "",
        "## Concurrency Summary",
        "",
        buildConcurrencyTable(summary),
        "",
        "## Security Scenario Comparison",
        "",
        buildSecurityScenarioTable(summary),
        "",
        "## Spoofing Resistance Matrix",
        "",
        buildSpoofingResistanceMatrix(summary),
        "",
        "## Mandatory RADIUS Comparison Dimensions",
        "",
        ...summary.radiusFiveDimensionComparison.map((item) =>
            `- ${item.dimension}: ${item.summary}`
        ),
        "",
        "## Limitations",
        "",
        ...summary.limitations.map((limitation) => `- ${limitation}`),
        ""
    ].join("\n");
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

async function writeComparisonFiles({
    resultsDir,
    timestamp,
    radiusResult,
    ldapResult,
    summary,
    observations
}) {
    await ensureResultsDirectory(resultsDir);

    const radiusPath = path.join(
        resultsDir,
        `radius-results-${timestamp}.json`
    );
    const ldapPath = path.join(
        resultsDir,
        `ldap-results-${timestamp}.json`
    );
    const summaryPath = path.join(
        resultsDir,
        `comparison-summary-${timestamp}.json`
    );
    const observationsPath = path.join(
        resultsDir,
        `comparison-observations-${timestamp}.csv`
    );
    const tablePath = path.join(
        resultsDir,
        `comparison-table-${timestamp}.md`
    );

    await writeJson(radiusPath, radiusResult);
    await writeJson(ldapPath, ldapResult);
    await writeJson(summaryPath, summary);
    await fs.writeFile(
        observationsPath,
        observationsToCsv(observations),
        "utf8"
    );
    await fs.writeFile(
        tablePath,
        buildMarkdownReport(summary),
        "utf8"
    );

    return {
        radiusPath,
        ldapPath,
        summaryPath,
        observationsPath,
        tablePath
    };
}

async function main() {
    const summaryPath = process.argv[2];

    if (!summaryPath) {
        console.error("Usage: node comparison/report-comparison.js comparison/results/comparison-summary-<timestamp>.json");
        process.exit(1);
    }

    const summary = JSON.parse(await fs.readFile(summaryPath, "utf8"));

    console.log(buildMarkdownReport(summary));
}

if (require.main === module) {
    main().catch((error) => {
        console.error(`Comparison report failed: ${error.message}`);
        process.exit(1);
    });
}

module.exports = {
    buildMarkdownReport,
    observationsToCsv,
    writeComparisonFiles
};
