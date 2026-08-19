import fs from "node:fs/promises";
import path from "node:path";

export function roundNumber(value, digits = 3) {
  if (!Number.isFinite(value)) {
    return null;
  }

  return Number(value.toFixed(digits));
}

export function calculateStats(values) {
  const numbers = values
    .filter((value) => Number.isFinite(value))
    .sort((left, right) => left - right);
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
  const p95Index = count >= 2 ? Math.ceil(0.95 * count) - 1 : null;

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

export function summarizeObservations(observations) {
  const measured = observations.filter((item) => item.measured !== false);
  const successful = measured.filter((item) => item.success === true).length;
  const failed = measured.filter((item) => item.success === false).length;
  const timeouts = measured.filter((item) => item.timeout === true).length;

  return {
    totalAttempts: measured.length,
    successfulTransactions: successful,
    failedTransactions: failed,
    successRatePercent: percent(successful, measured.length),
    failureRatePercent: percent(failed, measured.length),
    timeoutCount: timeouts,
    timeoutRatePercent: percent(timeouts, measured.length),
    submissionDurationMs: calculateStats(
      measured.map((item) => item.transactionSubmissionDurationMs)
    ),
    confirmationDurationMs: calculateStats(
      measured.map((item) => item.transactionConfirmationDurationMs)
    ),
    totalTransactionDurationMs: calculateStats(
      measured.map((item) => item.totalTransactionDurationMs)
    ),
    gasUsed: calculateStats(measured.map((item) => item.gasUsed))
  };
}

export function summarizeSequentialByBatch(observations, operation) {
  const summary = {};
  const batches = [...new Set(
    observations
      .filter((item) => item.operation === operation && item.batchSize)
      .map((item) => item.batchSize)
  )].sort((left, right) => left - right);

  for (const batchSize of batches) {
    summary[String(batchSize)] = summarizeObservations(
      observations.filter((item) =>
        item.operation === operation &&
        item.batchSize === batchSize
      )
    );
  }

  return summary;
}

export function summarizeConcurrency(observations, roundWallClock) {
  const summary = {};
  const levels = [...new Set(
    observations
      .filter((item) => item.operation === "AUTHENTICATION_EVENT_CONCURRENCY")
      .map((item) => item.concurrencyLevel)
      .filter(Boolean)
  )].sort((left, right) => left - right);

  for (const level of levels) {
    const levelObservations = observations.filter((item) =>
      item.operation === "AUTHENTICATION_EVENT_CONCURRENCY" &&
      item.concurrencyLevel === level
    );
    const baseSummary = summarizeObservations(levelObservations);
    const wallClockMs = roundWallClock
      .filter((round) => round.concurrencyLevel === level)
      .reduce((total, round) => total + round.wallClockMs, 0);

    summary[String(level)] = {
      concurrencyLevel: level,
      rounds: roundWallClock.filter((round) =>
        round.concurrencyLevel === level
      ),
      ...baseSummary,
      wallClockMs: roundNumber(wallClockMs),
      throughputPerSecond: wallClockMs > 0
        ? roundNumber(baseSummary.totalAttempts / (wallClockMs / 1000))
        : null
    };
  }

  return summary;
}

async function findLatestFile(directory, pattern) {
  let entries;

  try {
    entries = await fs.readdir(directory, {
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
    if (!entry.isFile() || !pattern.test(entry.name)) {
      continue;
    }

    const filePath = path.join(directory, entry.name);
    const stat = await fs.stat(filePath);

    candidates.push({
      fileName: entry.name,
      filePath,
      mtimeMs: stat.mtimeMs
    });
  }

  candidates.sort((left, right) =>
    right.mtimeMs - left.mtimeMs ||
    right.fileName.localeCompare(left.fileName)
  );

  return candidates[0] || null;
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

export async function loadFabricReference(repositoryRoot) {
  const evaluationDir = path.join(repositoryRoot, "evaluation", "results");
  const evaluation = await findLatestFile(
    evaluationDir,
    /^evaluation-summary-\d{4}-\d{2}-\d{2}T.+\.json$/
  );
  const concurrency = await findLatestFile(
    evaluationDir,
    /^concurrency-summary-\d{4}-\d{2}-\d{2}T.+\.json$/
  );
  const evaluationSummary = evaluation
    ? await readJson(evaluation.filePath)
    : null;
  const concurrencySummary = concurrency
    ? await readJson(concurrency.filePath)
    : null;
  const concurrency1 = concurrencySummary?.results?.["1"] || null;
  const concurrency50 = concurrencySummary?.results?.["50"] || null;

  return {
    filesUsed: {
      evaluationSummary: evaluation?.fileName || null,
      concurrencySummary: concurrency?.fileName || null
    },
    sequentialApplicationLevel: {
      averageChallengeDurationMs:
        evaluationSummary?.performance?.averageChallengeDurationMs ?? null,
      averageSigningDurationMs:
        evaluationSummary?.performance?.averageSigningDurationMs ?? null,
      averageVerificationDurationMs:
        evaluationSummary?.performance?.averageVerificationDurationMs ?? null,
      averageSpoofingCheckDurationMs:
        evaluationSummary?.performance?.averageSpoofingCheckDurationMs ?? null,
      averageTotalAuthenticationDurationMs:
        evaluationSummary?.performance?.averageTotalAuthenticationDurationMs ?? null
    },
    concurrency1: concurrency1
      ? {
        totalAttempts: concurrency1.totalAttempts,
        successRatePercent: concurrency1.successRatePercent,
        timeoutRatePercent: concurrency1.timeoutRatePercent,
        meanLatencyMs: concurrency1.meanLatencyMs,
        medianLatencyMs: concurrency1.medianLatencyMs,
        p95LatencyMs: concurrency1.p95LatencyMs,
        throughputPerSecond: concurrency1.throughputPerSecond
      }
      : null,
    concurrency50: concurrency50
      ? {
        totalAttempts: concurrency50.totalAttempts,
        successRatePercent: concurrency50.successRatePercent,
        timeoutRatePercent: concurrency50.timeoutRatePercent,
        meanLatencyMs: concurrency50.meanLatencyMs,
        medianLatencyMs: concurrency50.medianLatencyMs,
        p95LatencyMs: concurrency50.p95LatencyMs,
        throughputPerSecond: concurrency50.throughputPerSecond
      }
      : null,
    security:
      evaluationSummary?.security ?? null,
    platformTransactionTiming:
      "Not isolated in the existing Fabric Phase 8/11 datasets. Verification duration includes backend and Fabric transaction work but is not a pure Fabric commit-only metric."
  };
}

function formatMetric(value, suffix = "") {
  if (value === null || value === undefined) {
    return "n/a";
  }

  return `${value}${suffix}`;
}

export function buildComparisonSummary(ethereumResult, fabricReference) {
  const ethSequential50 =
    ethereumResult.sequential.authenticationEventByBatch["50"];
  const ethConcurrency50 =
    ethereumResult.concurrency.levels["50"];
  const authGas = ethereumResult.gas.authenticationEvent;

  return {
    generatedAt: ethereumResult.generatedAt,
    scope:
      "Phase 13 comparison between a local Ethereum development-network smart-contract benchmark and existing Hyperledger Fabric application evaluation results.",
    ethereum: {
      network: ethereumResult.network,
      framework: ethereumResult.tooling.hardhatVersion,
      solidityVersion: ethereumResult.tooling.solidityVersion,
      benchmarkLabel: "LOCAL ETHEREUM DEVELOPMENT NETWORK",
      sequentialAuthenticationEvent50: ethSequential50,
      concurrency50: ethConcurrency50,
      gas: ethereumResult.gas,
      deployment: ethereumResult.deployment
    },
    fabric: fabricReference,
    comparisonLevels: {
      platformTransactionComparison: {
        ethereum:
          "Measured as local Hardhat transaction submission through receipt for state-changing contract calls.",
        fabric:
          fabricReference.platformTransactionTiming
      },
      applicationLevelContext: {
        ethereum:
          "Not a full authentication application; no REST gateway, nonce service, P-256 verification, MAC/IP spoofing service, admin session, or dashboard path was ported.",
        fabric:
          "Existing metrics cover the implemented end-to-end authentication path: HTTPS gateway, nonce challenge, local P-256 signing, Fabric identity/status lookup, signature verification, spoofing classification, and immutable audit commit."
      }
    },
    table: [
      {
        metric: "Platform type",
        ethereum: "Ethereum-compatible local Hardhat development network",
        fabric: "Hyperledger Fabric permissioned network",
        interpretation:
          "The Ethereum result is local-development only; Fabric is the primary permissioned prototype."
      },
      {
        metric: "Contract language",
        ethereum: "Solidity 0.8.28",
        fabric: "JavaScript Fabric chaincode",
        interpretation:
          "Both provide programmable ledger logic, but with different execution and identity models."
      },
      {
        metric: "Permission model",
        ethereum: "Account-based local dev chain; public-style visibility model",
        fabric: "Permissioned MSP identities and organizations",
        interpretation:
          "Fabric better matches institutional control and membership requirements."
      },
      {
        metric: "Sequential transaction latency",
        ethereum:
          `${formatMetric(ethSequential50?.totalTransactionDurationMs?.mean, " ms")} mean auth-event tx at batch 50`,
        fabric:
          `${formatMetric(fabricReference.sequentialApplicationLevel.averageTotalAuthenticationDurationMs, " ms")} mean end-to-end auth`,
        interpretation:
          "Ethereum local contract tx is narrower than Fabric application-level authentication."
      },
      {
        metric: "Concurrency-50 latency",
        ethereum:
          `${formatMetric(ethConcurrency50?.totalTransactionDurationMs?.mean, " ms")} mean tx`,
        fabric:
          `${formatMetric(fabricReference.concurrency50?.meanLatencyMs, " ms")} mean end-to-end auth`,
        interpretation:
          "Fabric measurement includes gateway, signing, verification, spoofing, and audit work."
      },
      {
        metric: "Concurrency-50 success rate",
        ethereum:
          formatMetric(ethConcurrency50?.successRatePercent, "%"),
        fabric:
          formatMetric(fabricReference.concurrency50?.successRatePercent, "%"),
        interpretation:
          "Both are measured results from local/prototype environments."
      },
      {
        metric: "Observed throughput",
        ethereum:
          `${formatMetric(ethConcurrency50?.throughputPerSecond, " tx/s")} at concurrency 50`,
        fabric:
          `${formatMetric(fabricReference.concurrency50?.throughputPerSecond, " auth/s")} at concurrency 50`,
        interpretation:
          "Ethereum reports contract transactions; Fabric reports complete authentication flows."
      },
      {
        metric: "Gas requirement",
        ethereum:
          `${formatMetric(authGas?.mean)} mean gas units for auth-event tx`,
        fabric:
          "No Ethereum-style gas-metered transaction fee in this prototype",
        interpretation:
          "Fabric still has infrastructure operating cost; it is not universally cost-free."
      },
      {
        metric: "Immutable event support",
        ethereum: "SUPPORTED by transaction logs and stored events",
        fabric: "SUPPORTED by ledger audit events",
        interpretation:
          "Both can provide tamper-evident records, with different visibility and governance."
      },
      {
        metric: "Privacy/control",
        ethereum:
          "Local/public-style transaction visibility unless additional privacy layers are added",
        fabric:
          "Permissioned network with institutional membership and channel/private-data options",
        interpretation:
          "Fabric aligns more directly with institutional authentication privacy/control."
      },
      {
        metric: "Suitability for institutional authentication",
        ethereum:
          "Useful benchmark and possible public audit anchor; not implemented as the primary auth system",
        fabric:
          "Primary implementation platform for this project",
        interpretation:
          "Fabric remains a reasonable primary choice for controlled institutional identity and access workflows."
      }
    ],
    publicTestnet:
      "Public Ethereum testnet benchmarking was not performed; the formal Ethereum benchmark uses a local development network."
  };
}

function escapeCsv(value) {
  if (value === null || value === undefined) {
    return "";
  }

  const text = String(value);

  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, "\"\"")}"`;
  }

  return text;
}

export function observationsToCsv(observations) {
  const columns = [
    "timestamp",
    "operation",
    "batchSize",
    "concurrencyLevel",
    "round",
    "iteration",
    "success",
    "timeout",
    "transactionSubmissionDurationMs",
    "transactionConfirmationDurationMs",
    "totalTransactionDurationMs",
    "gasUsed",
    "blockNumber",
    "transactionHash",
    "notes"
  ];

  return [
    columns.join(","),
    ...observations.map((observation) =>
      columns.map((column) => escapeCsv(observation[column])).join(",")
    )
  ].join("\n") + "\n";
}

function comparisonTableToMarkdown(comparison) {
  return [
    "| Metric | Ethereum | Hyperledger Fabric | Interpretation |",
    "| --- | --- | --- | --- |",
    ...comparison.table.map((row) =>
      `| ${row.metric} | ${row.ethereum} | ${row.fabric} | ${row.interpretation} |`
    )
  ].join("\n");
}

export function buildMarkdownReport(comparison) {
  return [
    "# Ethereum and Hyperledger Fabric Benchmark Comparison",
    "",
    `Generated: ${comparison.generatedAt}`,
    "",
    "## Scope",
    "",
    comparison.scope,
    "",
    "## Comparison Levels",
    "",
    `- Platform transaction comparison: ${comparison.comparisonLevels.platformTransactionComparison.ethereum} Fabric: ${comparison.comparisonLevels.platformTransactionComparison.fabric}`,
    `- Application-level context: ${comparison.comparisonLevels.applicationLevelContext.ethereum} Fabric: ${comparison.comparisonLevels.applicationLevelContext.fabric}`,
    "",
    "## Report Table",
    "",
    comparisonTableToMarkdown(comparison),
    "",
    "## Public Testnet",
    "",
    comparison.publicTestnet,
    ""
  ].join("\n");
}

async function writeJson(filePath, data) {
  await fs.writeFile(
    filePath,
    `${JSON.stringify(data, null, 2)}\n`,
    "utf8"
  );
}

export async function writeOutputFiles({
  resultsDir,
  timestamp,
  ethereumResult,
  comparison,
  observations
}) {
  await fs.mkdir(resultsDir, {
    recursive: true
  });

  const ethereumPath = path.join(
    resultsDir,
    `ethereum-results-${timestamp}.json`
  );
  const observationsPath = path.join(
    resultsDir,
    `ethereum-observations-${timestamp}.csv`
  );
  const comparisonJsonPath = path.join(
    resultsDir,
    `ethereum-fabric-comparison-${timestamp}.json`
  );
  const comparisonMarkdownPath = path.join(
    resultsDir,
    `ethereum-fabric-comparison-${timestamp}.md`
  );

  await writeJson(ethereumPath, ethereumResult);
  await fs.writeFile(observationsPath, observationsToCsv(observations), "utf8");
  await writeJson(comparisonJsonPath, comparison);
  await fs.writeFile(
    comparisonMarkdownPath,
    buildMarkdownReport(comparison),
    "utf8"
  );

  return {
    ethereumPath,
    observationsPath,
    comparisonJsonPath,
    comparisonMarkdownPath
  };
}
