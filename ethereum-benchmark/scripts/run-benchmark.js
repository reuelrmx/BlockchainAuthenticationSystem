import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { network } from "hardhat";
import { keccak256, stringToHex } from "viem";

import {
  buildComparisonSummary,
  calculateStats,
  loadFabricReference,
  roundNumber,
  summarizeConcurrency,
  summarizeObservations,
  summarizeSequentialByBatch,
  writeOutputFiles
} from "./report-comparison.js";

const BATCH_SIZES = [10, 25, 50];
const CONCURRENCY_LEVELS = [1, 10, 25, 50];
const CONCURRENCY_ROUNDS = 3;
const RESULTS_DIR = "results";
const SOLIDITY_VERSION = "0.8.28";
const NETWORK_NAME = "hardhatMainnet";
const CHAIN_TYPE = "l1";

function timestampForFile(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, "-");
}

function hrtimeMs(start) {
  return Number(process.hrtime.bigint() - start) / 1_000_000;
}

function bytes32(label) {
  return keccak256(stringToHex(label));
}

function makeDid(prefix, timestamp, iteration) {
  return `did:ethereum:${prefix}:${timestamp}:${iteration}`;
}

function shortHash() {
  return crypto.randomBytes(8).toString("hex");
}

function normalizeReceipt(receipt) {
  return {
    status: receipt.status,
    gasUsed: Number(receipt.gasUsed),
    gasUsedRaw: receipt.gasUsed.toString(),
    effectiveGasPriceWei: receipt.effectiveGasPrice?.toString() || null,
    simulatedGasCostWei: receipt.effectiveGasPrice
      ? (receipt.effectiveGasPrice * receipt.gasUsed).toString()
      : null,
    blockNumber: Number(receipt.blockNumber),
    transactionHash: receipt.transactionHash
  };
}

async function measureTransaction({
  publicClient,
  operation,
  batchSize = null,
  concurrencyLevel = null,
  round = null,
  iteration = null,
  notes = "",
  send
}) {
  const timestamp = new Date().toISOString();
  const startedAt = process.hrtime.bigint();
  let hash;
  let submissionDurationMs;

  try {
    hash = await send();
    submissionDurationMs = roundNumber(hrtimeMs(startedAt));

    const confirmationStartedAt = process.hrtime.bigint();
    const receipt = await publicClient.waitForTransactionReceipt({
      hash
    });
    const confirmationDurationMs = roundNumber(hrtimeMs(confirmationStartedAt));
    const totalDurationMs = roundNumber(hrtimeMs(startedAt));
    const normalizedReceipt = normalizeReceipt(receipt);

    return {
      timestamp,
      operation,
      batchSize,
      concurrencyLevel,
      round,
      iteration,
      success: receipt.status === "success",
      timeout: false,
      transactionSubmissionDurationMs: submissionDurationMs,
      transactionConfirmationDurationMs: confirmationDurationMs,
      totalTransactionDurationMs: totalDurationMs,
      gasUsed: normalizedReceipt.gasUsed,
      blockNumber: normalizedReceipt.blockNumber,
      transactionHash: normalizedReceipt.transactionHash,
      receipt: normalizedReceipt,
      notes
    };
  } catch (error) {
    return {
      timestamp,
      operation,
      batchSize,
      concurrencyLevel,
      round,
      iteration,
      success: false,
      timeout: /timeout/i.test(error.message),
      transactionSubmissionDurationMs:
        submissionDurationMs || roundNumber(hrtimeMs(startedAt)),
      transactionConfirmationDurationMs: null,
      totalTransactionDurationMs: roundNumber(hrtimeMs(startedAt)),
      gasUsed: null,
      blockNumber: null,
      transactionHash: hash || null,
      receipt: null,
      notes: `${notes} Error: ${error.message}`
    };
  }
}

async function measureDeployment({ viem, publicClient }) {
  const startedAt = process.hrtime.bigint();
  const { contract, deploymentTransaction } =
    await viem.sendDeploymentTransaction("AuthenticationBenchmark");
  const submissionDurationMs = roundNumber(hrtimeMs(startedAt));
  const confirmationStartedAt = process.hrtime.bigint();
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: deploymentTransaction.hash
  });
  const confirmationDurationMs = roundNumber(hrtimeMs(confirmationStartedAt));

  return {
    contract,
    deployment: {
      operation: "DEPLOYMENT",
      transactionHash: deploymentTransaction.hash,
      contractAddress: contract.address,
      transactionSubmissionDurationMs: submissionDurationMs,
      transactionConfirmationDurationMs: confirmationDurationMs,
      totalTransactionDurationMs: roundNumber(hrtimeMs(startedAt)),
      receipt: normalizeReceipt(receipt),
      gasUsed: Number(receipt.gasUsed)
    }
  };
}

async function runSequentialBatch({
  publicClient,
  contract,
  timestamp,
  anchorDid,
  batchSize
}) {
  const observations = [];

  for (let iteration = 1; iteration <= batchSize; iteration += 1) {
    const eventId = bytes32(
      `phase13:auth:sequential:${timestamp}:${batchSize}:${iteration}:${shortHash()}`
    );

    observations.push(await measureTransaction({
      publicClient,
      contract,
      operation: "AUTHENTICATION_EVENT",
      batchSize,
      iteration,
      notes:
        "Authentication-equivalent authorization/audit transaction for an ACTIVE synthetic device.",
      send: () => contract.write.recordAuthenticationDecision([
        eventId,
        anchorDid,
        true,
        "VALID_SIGNATURE"
      ])
    }));
  }

  return observations;
}

async function runConcurrentRounds({
  viem,
  publicClient,
  contract,
  recorderContracts,
  timestamp,
  anchorDid
}) {
  const observations = [];
  const roundWallClock = [];

  for (const concurrencyLevel of CONCURRENCY_LEVELS) {
    for (let round = 1; round <= CONCURRENCY_ROUNDS; round += 1) {
      const startedAt = process.hrtime.bigint();
      const attempts = await Promise.all(
        Array.from({ length: concurrencyLevel }, (_, index) => {
          const iteration = index + 1;
          const recorderContract = recorderContracts[index];
          const eventId = bytes32(
            `phase13:auth:concurrency:${timestamp}:${concurrencyLevel}:${round}:${iteration}:${shortHash()}`
          );

          return measureTransaction({
            publicClient,
            contract,
            operation: "AUTHENTICATION_EVENT_CONCURRENCY",
            concurrencyLevel,
            round,
            iteration,
            notes:
              "Concurrent authentication-equivalent transaction sent by a distinct authorized benchmark recorder account.",
            send: () => recorderContract.write.recordAuthenticationDecision([
              eventId,
              anchorDid,
              true,
              "VALID_SIGNATURE"
            ])
          });
        })
      );
      const wallClockMs = roundNumber(hrtimeMs(startedAt));

      roundWallClock.push({
        concurrencyLevel,
        round,
        attempts: concurrencyLevel,
        wallClockMs,
        successes: attempts.filter((item) => item.success).length,
        failures: attempts.filter((item) => !item.success).length,
        timeouts: attempts.filter((item) => item.timeout).length
      });
      observations.push(...attempts);
    }
  }

  return {
    observations,
    roundWallClock
  };
}

async function main() {
  const benchmarkTimestamp = timestampForFile();
  const repositoryRoot = path.resolve(process.cwd(), "..");
  const resultsDir = path.resolve(process.cwd(), RESULTS_DIR);
  const packageJson = JSON.parse(
    await fs.readFile(path.resolve(process.cwd(), "package.json"), "utf8")
  );
  const hardhatPackageJson = JSON.parse(
    await fs.readFile(
      path.resolve(process.cwd(), "node_modules", "hardhat", "package.json"),
      "utf8"
    )
  );

  const connection = await network.create({
    network: NETWORK_NAME,
    chainType: CHAIN_TYPE
  });
  const { viem, networkConfig } = connection;
  const publicClient = await viem.getPublicClient();
  const walletClients = await viem.getWalletClients();
  const administrator = walletClients[0];
  const owner = walletClients[1];
  const recorderWallets = walletClients.slice(0, Math.max(...CONCURRENCY_LEVELS));
  const chainId = await publicClient.getChainId();
  const initialBlockNumber = await publicClient.getBlockNumber();
  const gasPrice = await publicClient.getGasPrice();

  const { contract, deployment } = await measureDeployment({
    viem,
    publicClient
  });

  const observations = [];
  const anchorDid = makeDid("anchor", benchmarkTimestamp, 1);
  const anchorRegistration = await measureTransaction({
    publicClient,
    operation: "ANCHOR_DEVICE_REGISTRATION",
    notes:
      "Synthetic ACTIVE device used as the target for authentication-equivalent event benchmarks.",
    send: () => contract.write.registerDevice([
      anchorDid,
      bytes32(`phase13:anchor:${benchmarkTimestamp}`),
      owner.account.address
    ])
  });

  observations.push(anchorRegistration);

  for (const recorder of recorderWallets) {
    if (recorder.account.address === administrator.account.address) {
      continue;
    }

    await contract.write.setRecorderAuthorization([
      recorder.account.address,
      true
    ]);
  }

  const recorderContracts = await Promise.all(
    recorderWallets.map((recorder) =>
      viem.getContractAt("AuthenticationBenchmark", contract.address, {
        client: {
          public: publicClient,
          wallet: recorder
        }
      })
    )
  );

  const registrationSamples = [];

  for (let iteration = 1; iteration <= 10; iteration += 1) {
    const did = makeDid("registration", benchmarkTimestamp, iteration);

    registrationSamples.push(await measureTransaction({
      publicClient,
      operation: "DEVICE_REGISTRATION",
      iteration,
      notes: "Synthetic Ethereum benchmark device registration transaction.",
      send: () => contract.write.registerDevice([
        did,
        bytes32(`phase13:registration:${benchmarkTimestamp}:${iteration}`),
        owner.account.address
      ])
    }));
  }

  observations.push(...registrationSamples);

  const statusDid = makeDid("status", benchmarkTimestamp, 1);

  observations.push(await measureTransaction({
    publicClient,
    operation: "STATUS_TEST_DEVICE_REGISTRATION",
    notes: "Synthetic device used for repeated status update measurement.",
    send: () => contract.write.registerDevice([
      statusDid,
      bytes32(`phase13:status:${benchmarkTimestamp}`),
      owner.account.address
    ])
  }));

  const statusSamples = [];

  for (let iteration = 1; iteration <= 10; iteration += 1) {
    const suspend = iteration % 2 === 1;

    statusSamples.push(await measureTransaction({
      publicClient,
      operation: "STATUS_CHANGE",
      iteration,
      notes: suspend
        ? "Suspend synthetic benchmark device."
        : "Reactivate synthetic benchmark device.",
      send: () => suspend
        ? contract.write.suspendDevice([statusDid])
        : contract.write.activateDevice([statusDid])
    }));
  }

  observations.push(...statusSamples);

  for (const batchSize of BATCH_SIZES) {
    observations.push(...await runSequentialBatch({
      publicClient,
      contract,
      timestamp: benchmarkTimestamp,
      anchorDid,
      batchSize
    }));
  }

  const concurrencyRun = await runConcurrentRounds({
    viem,
    publicClient,
    contract,
    recorderContracts,
    timestamp: benchmarkTimestamp,
    anchorDid
  });

  observations.push(...concurrencyRun.observations);

  const finalBlockNumber = await publicClient.getBlockNumber();
  const authenticationEventObservations = observations.filter((item) =>
    item.operation === "AUTHENTICATION_EVENT" ||
    item.operation === "AUTHENTICATION_EVENT_CONCURRENCY"
  );

  const ethereumResult = {
    generatedAt: new Date().toISOString(),
    label: "LOCAL ETHEREUM DEVELOPMENT NETWORK",
    tooling: {
      nodeVersion: process.version,
      npmPackageVersion: packageJson.version,
      hardhatVersion: hardhatPackageJson.version,
      solidityVersion: SOLIDITY_VERSION,
      viemToolbox:
        packageJson.devDependencies["@nomicfoundation/hardhat-toolbox-viem"]
    },
    cryptographicComparability: {
      decision:
        "Benchmark equivalent authorization/event smart-contract execution rather than porting Fabric's ECDSA P-256 verification to Solidity.",
      basis:
        "Ethereum's native signature/account model is secp256k1-oriented. The Fabric prototype verifies device ECDSA P-256 signatures, so forcing P-256 verification on-chain would add custom cryptographic code and distort the platform benchmark."
    },
    network: {
      networkName: NETWORK_NAME,
      chainType: CHAIN_TYPE,
      chainId,
      hardhatNetworkType: networkConfig.type,
      blockProduction:
        "Hardhat EDR simulated L1 network with automining enabled; each accepted transaction is mined locally and confirmation is receipt retrieval.",
      accountModel:
        "Ethereum account-based model; one administrator configures synthetic benchmark recorder accounts, and concurrent transactions are submitted by distinct pre-funded local accounts to avoid nonce collisions.",
      configuredAccountCount: 60,
      gasPriceWei: gasPrice.toString(),
      initialBlockNumber: Number(initialBlockNumber),
      finalBlockNumber: Number(finalBlockNumber)
    },
    deployment,
    operationsMeasured: [
      "DEVICE_REGISTRATION",
      "AUTHENTICATION_EVENT",
      "STATUS_CHANGE"
    ],
    sequential: {
      requestedBatchSizes: BATCH_SIZES,
      authenticationEventByBatch: summarizeSequentialByBatch(
        observations,
        "AUTHENTICATION_EVENT"
      )
    },
    concurrency: {
      levelsRequested: CONCURRENCY_LEVELS,
      roundsPerLevel: CONCURRENCY_ROUNDS,
      nonceManagement:
        "Multiple pre-funded local Hardhat accounts are authorized as benchmark recorders; each concurrent transaction uses a distinct account where possible.",
      levels: summarizeConcurrency(
        observations,
        concurrencyRun.roundWallClock
      )
    },
    gas: {
      deployment: {
        gasUsed: deployment.gasUsed,
        simulatedGasCostWei: deployment.receipt.simulatedGasCostWei
      },
      deviceRegistration: calculateStats(
        registrationSamples.map((item) => item.gasUsed)
      ),
      authenticationEvent: calculateStats(
        authenticationEventObservations.map((item) => item.gasUsed)
      ),
      statusChange: calculateStats(
        statusSamples.map((item) => item.gasUsed)
      )
    },
    publicTestnet:
      "Public Ethereum testnet benchmarking was not performed; no testnet RPC endpoint or test ETH was configured for this Phase 13 run.",
    observations
  };

  const fabricReference = await loadFabricReference(repositoryRoot);
  const comparison = buildComparisonSummary(ethereumResult, fabricReference);
  const outputFiles = await writeOutputFiles({
    resultsDir,
    timestamp: benchmarkTimestamp,
    ethereumResult,
    comparison,
    observations
  });

  console.log(JSON.stringify({
    success: true,
    generatedAt: ethereumResult.generatedAt,
    ethereum: {
      label: ethereumResult.label,
      chainId,
      contractAddress: deployment.contractAddress,
      deploymentGasUsed: deployment.gasUsed,
      sequential50:
        ethereumResult.sequential.authenticationEventByBatch["50"],
      concurrency50:
        ethereumResult.concurrency.levels["50"],
      authenticationEventGas:
        ethereumResult.gas.authenticationEvent
    },
    fabricFilesUsed: fabricReference.filesUsed,
    outputFiles
  }, null, 2));
}

main().catch((error) => {
  console.error(`Ethereum benchmark failed: ${error.message}`);
  process.exit(1);
});
