#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const {
    SCENARIO_NAMES,
    buildScenarios
} = require("../attacks/simulation/scenarios");
const {
    summarizeResults,
    roundNumber
} = require("./statistics");
const {
    buildFinalSummary,
    writeBatchResult,
    writeSummaryResults,
    compactBatchConsoleSummary
} = require("./report-results");

const execFileAsync = promisify(execFile);

const DEFAULT_API_URL = "http://localhost:3000";
const DEFAULT_RESULTS_DIR = "evaluation/results";
const DEFAULT_DEVICE_DIRECTORY =
    "gateway/device-client/devices/33bad912-4914-449f-b674-7c5fba40d9d8";
const PRIMARY_DID =
    "did:fabric:b9f2e316-3d27-4a45-a044-128d760fff26";
const DEFAULT_BATCH_SIZES = [10, 25, 50];
const DEFAULT_WARMUP_ATTEMPTS = 3;
const TIMESTAMP_SAFE_PATTERN = /[:.]/g;
const EXPIRED_CHALLENGE_GRACE_MS = 250;

function usage() {
    return [
        "Usage:",
        "  node evaluation/run-evaluation.js",
        "  node evaluation/run-evaluation.js --device gateway/device-client/devices/<folder>",
        "",
        "Options:",
        "  --api <url>                 API base URL, default http://localhost:3000",
        "  --device <directory>        Primary local device directory",
        "  --batches <list>            Comma-separated batch sizes, default 10,25,50",
        "  --warmup <count>            Legitimate warm-up attempts, default 3",
        "  --results-dir <directory>   Result directory, default evaluation/results",
        "  --suspended-device <dir>    Optional status-test device directory",
        "  --revoked-device <dir>      Optional revoked-test device directory",
        "  --skip-expired-audit-check  Skip the one-off expired challenge audit probe",
        "  --help                      Show this message"
    ].join("\n");
}

function getArg(name) {
    const flag = `--${name}`;
    const withEquals = `${flag}=`;
    const index = process.argv.indexOf(flag);

    if (index !== -1 && process.argv[index + 1]) {
        return process.argv[index + 1];
    }

    const match = process.argv.find((arg) => arg.startsWith(withEquals));

    return match ? match.slice(withEquals.length) : null;
}

function hasFlag(name) {
    return process.argv.includes(`--${name}`);
}

function parsePositiveInteger(value, defaultValue, label) {
    if (value === null || value === undefined || value === "") {
        return defaultValue;
    }

    const parsed = Number(value);

    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new Error(`${label} must be a positive integer`);
    }

    return parsed;
}

function parseBatchSizes(value) {
    if (!value) {
        return DEFAULT_BATCH_SIZES;
    }

    const sizes = value
        .split(",")
        .map((part) => Number(part.trim()))
        .filter((size) => Number.isSafeInteger(size) && size > 0);

    if (sizes.length === 0) {
        throw new Error("At least one valid batch size is required");
    }

    return sizes;
}

function absoluteFromCwd(value) {
    return path.resolve(process.cwd(), value);
}

function hrtimeMs(start) {
    return Number(process.hrtime.bigint() - start) / 1_000_000;
}

function roundDuration(value) {
    return roundNumber(value, 3);
}

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

function joinApiUrl(apiUrl, endpoint) {
    return `${apiUrl.replace(/\/$/, "")}${endpoint}`;
}

function jsonHeaders(extraHeaders = {}) {
    return {
        "Content-Type": "application/json",
        ...extraHeaders
    };
}

async function readJsonFile(filePath) {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function readTextFile(filePath) {
    return fs.readFile(filePath, "utf8");
}

async function requestJson(apiUrl, endpoint, options = {}) {
    const start = process.hrtime.bigint();
    const response = await fetch(joinApiUrl(apiUrl, endpoint), {
        method: options.method || "GET",
        headers: jsonHeaders(options.headers),
        body: options.body === undefined
            ? undefined
            : JSON.stringify(options.body)
    });
    const rawBody = await response.text();
    const durationMs = roundDuration(hrtimeMs(start));
    let body = null;

    if (rawBody) {
        try {
            body = JSON.parse(rawBody);
        } catch {
            body = {
                rawBody
            };
        }
    }

    return {
        statusCode: response.status,
        ok: response.ok,
        body,
        durationMs
    };
}

async function loadDeviceCredential(deviceDirectory) {
    const directory = absoluteFromCwd(deviceDirectory);
    const identityPath = path.join(directory, "identity.json");
    const privateKeyPath = path.join(directory, "private-key.pem");
    const identity = await readJsonFile(identityPath);

    if (typeof identity.did !== "string" || identity.did.trim() === "") {
        throw new Error(`DID is missing from ${identityPath}`);
    }

    const privateKey = await readTextFile(privateKeyPath);

    return {
        directory,
        identity,
        did: identity.did.trim(),
        privateKey
    };
}

async function loadDeviceIdentity(deviceDirectory) {
    const directory = absoluteFromCwd(deviceDirectory);
    const identityPath = path.join(directory, "identity.json");
    const identity = await readJsonFile(identityPath);

    if (typeof identity.did !== "string" || identity.did.trim() === "") {
        throw new Error(`DID is missing from ${identityPath}`);
    }

    return {
        directory,
        identity,
        did: identity.did.trim()
    };
}

function requireDid(credential) {
    if (credential.did !== PRIMARY_DID) {
        throw new Error(
            `Primary evaluation DID must be ${PRIMARY_DID}; found ${credential.did}`
        );
    }
}

async function getDeviceRecord(apiUrl, did) {
    const response = await requestJson(
        apiUrl,
        `/api/devices/${encodeURIComponent(did)}`
    );

    if (!response.ok || response.body?.success !== true) {
        throw new Error(
            `Unable to load device ${did}; HTTP ${response.statusCode}`
        );
    }

    return response.body.data;
}

async function requestChallenge(apiUrl, did) {
    return requestJson(apiUrl, "/api/auth/challenge", {
        method: "POST",
        body: {
            did
        }
    });
}

function validateChallenge(response, did) {
    const data = response.body?.data;

    if (
        !response.ok ||
        response.body?.success !== true ||
        typeof data?.challengeId !== "string" ||
        typeof data?.challengePayload !== "string" ||
        typeof data?.expiresAt !== "string"
    ) {
        return null;
    }

    if (!data.challengePayload.startsWith(`${did}|${data.challengeId}|`)) {
        return null;
    }

    return data;
}

function signChallengePayload(privateKey, challengePayload) {
    const start = process.hrtime.bigint();
    const signer = crypto.createSign("SHA256");

    signer.update(challengePayload);
    signer.end();

    return {
        signature: signer.sign(privateKey, "base64"),
        signingDurationMs: roundDuration(hrtimeMs(start))
    };
}

function buildSimulationHeaders(scenario) {
    const headers = {};

    if (scenario.simulatedIpAddress) {
        headers["X-Simulated-Source-IP"] = scenario.simulatedIpAddress;
    }

    if (scenario.simulatedMacAddress) {
        headers["X-Simulated-Source-MAC"] =
            scenario.simulatedMacAddress;
    }

    return headers;
}

async function submitVerification(apiUrl, scenario, proof) {
    return requestJson(apiUrl, "/api/auth/verify", {
        method: "POST",
        headers: buildSimulationHeaders(scenario),
        body: proof
    });
}

function responseDecision(response) {
    return response.body?.decision || (response.ok ? "GRANTED" : "DENIED");
}

function responseClassification(response) {
    return response.body?.spoofingClassification || "NOT_EVALUATED";
}

function extractAuditEventIds(...responses) {
    return responses
        .map((response) => response?.body?.auditEventId)
        .filter((eventId) => typeof eventId === "string" && eventId !== "");
}

function createResult({
    batchSize,
    scenario,
    iteration,
    did,
    timestamp = new Date().toISOString()
}) {
    return {
        batchSize,
        scenario: scenario.name,
        iteration,
        did,
        expectedDecision: scenario.expectedDecision,
        actualDecision: null,
        expectedClassification:
            scenario.expectedSpoofingClassification,
        actualClassification: null,
        expectedHttpStatus: scenario.expectedHttpStatus,
        challengeDurationMs: null,
        signingDurationMs: null,
        verificationDurationMs: null,
        spoofingCheckDurationMs: null,
        totalAuthenticationDurationMs: null,
        httpStatus: null,
        auditEventId: null,
        auditEventIds: [],
        auditConfirmed: false,
        testPassed: false,
        timestamp
    };
}

function scenarioMatchesExpectation(result) {
    return (
        result.actualDecision === result.expectedDecision &&
        result.actualClassification === result.expectedClassification &&
        result.httpStatus === result.expectedHttpStatus
    );
}

function applyFailedChallenge(result, challengeResponse, totalStart) {
    result.httpStatus = challengeResponse.statusCode;
    result.actualDecision = responseDecision(challengeResponse);
    result.actualClassification = responseClassification(challengeResponse);
    result.reason = challengeResponse.body?.message ||
        challengeResponse.body?.reason ||
        "Challenge request failed";
    result.totalAuthenticationDurationMs = roundDuration(
        hrtimeMs(totalStart)
    );
    result.testPassed = scenarioMatchesExpectation(result);
}

async function runSignedScenario({
    apiUrl,
    credential,
    scenario,
    iteration,
    batchSize
}) {
    const totalStart = process.hrtime.bigint();
    const result = createResult({
        batchSize,
        scenario,
        iteration,
        did: credential.did
    });
    const challengeResponse = await requestChallenge(apiUrl, credential.did);

    result.challengeDurationMs = challengeResponse.durationMs;

    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        applyFailedChallenge(result, challengeResponse, totalStart);

        return result;
    }

    let signature;

    if (scenario.invalidSignature) {
        signature = Buffer
            .from("phase-8-invalid-signature")
            .toString("base64");
        result.signingDurationMs = null;
    } else {
        const signed = signChallengePayload(
            credential.privateKey,
            challenge.challengePayload
        );

        signature = signed.signature;
        result.signingDurationMs = signed.signingDurationMs;
    }

    const verificationResponse = await submitVerification(
        apiUrl,
        scenario,
        {
            did: credential.did,
            challengeId: challenge.challengeId,
            signature
        }
    );

    result.verificationDurationMs = verificationResponse.durationMs;
    result.httpStatus = verificationResponse.statusCode;
    result.actualDecision = responseDecision(verificationResponse);
    result.actualClassification =
        responseClassification(verificationResponse);
    result.spoofingCheckDurationMs =
        verificationResponse.body?.spoofingCheckDurationMs ?? null;
    result.totalAuthenticationDurationMs = roundDuration(
        hrtimeMs(totalStart)
    );
    result.reason = verificationResponse.body?.reason || null;
    result.auditEventId = verificationResponse.body?.auditEventId || null;
    result.auditEventIds = extractAuditEventIds(verificationResponse);
    result.testPassed = scenarioMatchesExpectation(result);

    return result;
}

async function runReplayScenario({
    apiUrl,
    credential,
    scenario,
    iteration,
    batchSize
}) {
    const totalStart = process.hrtime.bigint();
    const result = createResult({
        batchSize,
        scenario,
        iteration,
        did: credential.did
    });
    const challengeResponse = await requestChallenge(apiUrl, credential.did);

    result.challengeDurationMs = challengeResponse.durationMs;

    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        applyFailedChallenge(result, challengeResponse, totalStart);

        return result;
    }

    const signed = signChallengePayload(
        credential.privateKey,
        challenge.challengePayload
    );
    const proof = {
        did: credential.did,
        challengeId: challenge.challengeId,
        signature: signed.signature
    };
    const firstVerification = await submitVerification(
        apiUrl,
        scenario,
        proof
    );
    const secondVerification = await submitVerification(
        apiUrl,
        scenario,
        proof
    );

    result.signingDurationMs = signed.signingDurationMs;
    result.verificationDurationMs = secondVerification.durationMs;
    result.initialVerificationDurationMs = firstVerification.durationMs;
    result.replayVerificationDurationMs = secondVerification.durationMs;
    result.httpStatus = secondVerification.statusCode;
    result.actualDecision = responseDecision(secondVerification);
    result.actualClassification =
        responseClassification(secondVerification);
    result.spoofingCheckDurationMs =
        secondVerification.body?.spoofingCheckDurationMs ?? null;
    result.totalAuthenticationDurationMs = roundDuration(
        hrtimeMs(totalStart)
    );
    result.reason = secondVerification.body?.reason || null;
    result.auditEventIds = extractAuditEventIds(
        firstVerification,
        secondVerification
    );
    result.auditEventId = result.auditEventIds[1] ||
        result.auditEventIds[0] ||
        null;
    result.replay = {
        challengeId: challenge.challengeId,
        firstHttpStatus: firstVerification.statusCode,
        firstDecision: responseDecision(firstVerification),
        firstClassification: responseClassification(firstVerification),
        firstAuditEventId: firstVerification.body?.auditEventId || null,
        secondHttpStatus: secondVerification.statusCode,
        secondDecision: responseDecision(secondVerification),
        secondClassification: responseClassification(secondVerification),
        secondAuditEventId: secondVerification.body?.auditEventId || null
    };
    result.testPassed =
        firstVerification.statusCode === 200 &&
        result.replay.firstDecision ===
            scenario.replayExpectedFirstDecision &&
        result.replay.firstClassification ===
            scenario.replayExpectedFirstSpoofingClassification &&
        scenarioMatchesExpectation(result);

    return result;
}

async function runStatusScenario({
    apiUrl,
    scenario,
    target,
    iteration,
    batchSize
}) {
    const result = createResult({
        batchSize,
        scenario,
        iteration,
        did: target?.did || null
    });

    if (!target) {
        result.skipped = true;
        result.reason = `No ${scenario.statusScenario} test identity found`;

        return result;
    }

    const totalStart = process.hrtime.bigint();
    const challengeResponse = await requestChallenge(apiUrl, target.did);

    result.challengeDurationMs = challengeResponse.durationMs;
    result.httpStatus = challengeResponse.statusCode;
    result.actualDecision = responseDecision(challengeResponse);
    result.actualClassification = responseClassification(challengeResponse);
    result.reason = challengeResponse.body?.message ||
        challengeResponse.body?.reason ||
        null;
    result.totalAuthenticationDurationMs = roundDuration(
        hrtimeMs(totalStart)
    );
    result.testPassed = scenarioMatchesExpectation(result);

    return result;
}

async function patchDeviceStatus(apiUrl, did, action, body) {
    return requestJson(apiUrl, `/api/devices/${encodeURIComponent(did)}/${action}`, {
        method: "PATCH",
        body
    });
}

async function listSiblingDeviceDirectories(primaryDeviceDirectory) {
    const parentDirectory = path.dirname(primaryDeviceDirectory);
    const entries = await fs.readdir(parentDirectory, {
        withFileTypes: true
    });

    return entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => path.join(parentDirectory, entry.name));
}

async function loadCandidateDeviceDirectories(primaryDeviceDirectory) {
    const directories = await listSiblingDeviceDirectories(
        primaryDeviceDirectory
    );
    const candidates = [];

    for (const directory of directories) {
        try {
            candidates.push(await loadDeviceIdentity(directory));
        } catch {
            // Some folders may not be generated device identities.
        }
    }

    return candidates;
}

function textIncludesSuspend(value) {
    return String(value || "").toLowerCase().includes("suspend");
}

async function enrichCandidate(apiUrl, candidate) {
    const record = await getDeviceRecord(apiUrl, candidate.did);

    return {
        ...candidate,
        record,
        status: String(record.status || "").toUpperCase()
    };
}

async function findStatusTargets({
    apiUrl,
    credential,
    suspendedDeviceDirectory,
    revokedDeviceDirectory
}) {
    const candidates = await loadCandidateDeviceDirectories(
        credential.directory
    );
    const enrichedCandidates = [];

    for (const candidate of candidates) {
        if (candidate.did === credential.did) {
            continue;
        }

        try {
            enrichedCandidates.push(await enrichCandidate(apiUrl, candidate));
        } catch {
            // The local identity may not exist in the current ledger.
        }
    }

    let suspendedTarget = null;
    let revokedTarget = null;

    if (suspendedDeviceDirectory) {
        suspendedTarget = await enrichCandidate(
            apiUrl,
            await loadDeviceIdentity(suspendedDeviceDirectory)
        );
    } else {
        suspendedTarget = enrichedCandidates.find((candidate) =>
            candidate.did !== PRIMARY_DID &&
            candidate.status !== "REVOKED" &&
            (
                textIncludesSuspend(candidate.identity.owner) ||
                textIncludesSuspend(candidate.record.owner)
            )
        ) || null;
    }

    if (revokedDeviceDirectory) {
        revokedTarget = await enrichCandidate(
            apiUrl,
            await loadDeviceIdentity(revokedDeviceDirectory)
        );
    } else {
        revokedTarget = enrichedCandidates.find((candidate) =>
            candidate.did !== PRIMARY_DID &&
            candidate.status === "REVOKED"
        ) || null;
    }

    if (suspendedTarget?.did === PRIMARY_DID) {
        throw new Error("Refusing to suspend the primary evaluation device");
    }

    if (revokedTarget?.did === PRIMARY_DID) {
        throw new Error("Refusing to use the primary evaluation device as revoked target");
    }

    return {
        suspendedTarget,
        revokedTarget
    };
}

async function runWithTemporarySuspension({
    apiUrl,
    suspendedTarget,
    iterations,
    scenario,
    batchSize
}) {
    const results = [];

    if (!suspendedTarget) {
        for (let iteration = 1; iteration <= iterations; iteration += 1) {
            results.push(await runStatusScenario({
                apiUrl,
                scenario,
                target: null,
                iteration,
                batchSize
            }));
        }

        return {
            results,
            cleanup: {
                attempted: false,
                restoredToActive: false,
                reason: "No suspend-test identity was available"
            }
        };
    }

    const originalStatus = String(suspendedTarget.status || "").toUpperCase();
    const cleanup = {
        did: suspendedTarget.did,
        originalStatus,
        temporarilySuspended: false,
        attempted: false,
        restoredToActive: false
    };

    try {
        if (originalStatus === "ACTIVE") {
            const suspendResponse = await patchDeviceStatus(
                apiUrl,
                suspendedTarget.did,
                "suspend",
                {
                    reason: "Phase 8 controlled evaluation"
                }
            );

            cleanup.attempted = true;

            if (!suspendResponse.ok) {
                throw new Error(
                    `Unable to suspend ${suspendedTarget.did}; HTTP ${suspendResponse.statusCode}`
                );
            }

            cleanup.temporarilySuspended = true;
        }

        for (let iteration = 1; iteration <= iterations; iteration += 1) {
            results.push(await runStatusScenario({
                apiUrl,
                scenario,
                target: suspendedTarget,
                iteration,
                batchSize
            }));
        }
    } finally {
        if (cleanup.temporarilySuspended) {
            const activateResponse = await patchDeviceStatus(
                apiUrl,
                suspendedTarget.did,
                "activate"
            );

            cleanup.restoredToActive = activateResponse.ok;
            cleanup.restoreHttpStatus = activateResponse.statusCode;
        }
    }

    return {
        results,
        cleanup
    };
}

async function correlateAuditEvents(apiUrl, results) {
    const eventIds = [
        ...new Set(results.flatMap((result) => {
            if (Array.isArray(result.auditEventIds)) {
                return result.auditEventIds;
            }

            return result.auditEventId ? [result.auditEventId] : [];
        }))
    ];
    const events = [];

    for (const eventId of eventIds) {
        const response = await requestJson(
            apiUrl,
            `/api/audit/authentication/${encodeURIComponent(eventId)}`
        );

        events.push({
            eventId,
            httpStatus: response.statusCode,
            confirmed: response.ok &&
                response.body?.success === true &&
                response.body?.data?.eventId === eventId,
            decision: response.body?.data?.decision || null,
            reason: response.body?.data?.reason || null,
            spoofingClassification:
                response.body?.data?.spoofingClassification || null
        });
    }

    const confirmed = new Set(
        events
            .filter((event) => event.confirmed)
            .map((event) => event.eventId)
    );

    for (const result of results) {
        const resultEventIds = result.auditEventIds?.length
            ? result.auditEventIds
            : result.auditEventId ? [result.auditEventId] : [];

        result.auditConfirmed = resultEventIds.length > 0 &&
            resultEventIds.every((eventId) => confirmed.has(eventId));
    }

    return {
        checked: events.length,
        confirmed: events.filter((event) => event.confirmed).length,
        events
    };
}

async function runBatch({
    apiUrl,
    credential,
    scenarios,
    batchSize,
    timestamp,
    resultsDir,
    suspendedTarget,
    revokedTarget,
    environment
}) {
    const results = [];
    const cleanup = {
        suspendedDevice: null
    };

    console.warn(`Starting Phase 8 batch: ${batchSize} iterations`);

    for (let iteration = 1; iteration <= batchSize; iteration += 1) {
        for (const scenario of scenarios) {
            if (scenario.name === SCENARIO_NAMES.SUSPENDED) {
                continue;
            }

            if (scenario.name === SCENARIO_NAMES.REVOKED) {
                results.push(await runStatusScenario({
                    apiUrl,
                    scenario,
                    target: revokedTarget,
                    iteration,
                    batchSize
                }));
                continue;
            }

            if (scenario.replay) {
                results.push(await runReplayScenario({
                    apiUrl,
                    credential,
                    scenario,
                    iteration,
                    batchSize
                }));
                continue;
            }

            results.push(await runSignedScenario({
                apiUrl,
                credential,
                scenario,
                iteration,
                batchSize
            }));
        }
    }

    const suspendedScenario = scenarios.find((scenario) =>
        scenario.name === SCENARIO_NAMES.SUSPENDED
    );

    if (suspendedScenario) {
        const suspendedRun = await runWithTemporarySuspension({
            apiUrl,
            suspendedTarget,
            iterations: batchSize,
            scenario: suspendedScenario,
            batchSize
        });

        results.push(...suspendedRun.results);
        cleanup.suspendedDevice = suspendedRun.cleanup;
    }

    const auditCorrelation = await correlateAuditEvents(apiUrl, results);
    const summary = summarizeResults(results);
    const batchReport = {
        generatedAt: new Date().toISOString(),
        batchSize,
        environment,
        summary,
        auditCorrelation,
        cleanup,
        results
    };
    const outputPath = await writeBatchResult({
        resultsDir,
        batchSize,
        timestamp,
        report: batchReport
    });

    console.log(JSON.stringify({
        outputPath,
        ...compactBatchConsoleSummary(batchReport)
    }, null, 2));

    return {
        batchReport,
        outputPath
    };
}

function validateRegisteredContext(record) {
    const registeredMacAddress = record?.registeredMacAddress;
    const registeredIpAddress = record?.registeredIpAddress;

    if (
        typeof registeredMacAddress !== "string" ||
        registeredMacAddress.trim() === "" ||
        typeof registeredIpAddress !== "string" ||
        registeredIpAddress.trim() === ""
    ) {
        throw new Error("Primary device record is missing MAC/IP context");
    }

    return {
        registeredMacAddress: registeredMacAddress.trim(),
        registeredIpAddress: registeredIpAddress.trim()
    };
}

async function checkHealth(apiUrl) {
    const response = await requestJson(apiUrl, "/api/health");

    if (
        !response.ok ||
        response.body?.success !== true ||
        response.body?.fabric !== "connected"
    ) {
        throw new Error(
            `Fabric health check failed; HTTP ${response.statusCode}`
        );
    }

    return response;
}

async function checkAuditApi(apiUrl) {
    const response = await requestJson(apiUrl, "/api/audit/authentication");

    if (!response.ok || response.body?.success !== true) {
        throw new Error(`Audit API check failed; HTTP ${response.statusCode}`);
    }

    return response;
}

async function checkResultsWritable(resultsDir) {
    await fs.mkdir(resultsDir, {
        recursive: true
    });

    const probePath = path.join(
        resultsDir,
        `.write-test-${process.pid}`
    );

    await fs.writeFile(probePath, "ok\n", "utf8");
    await fs.unlink(probePath);
}

async function commandOrNull(command, args, options = {}) {
    try {
        const { stdout } = await execFileAsync(command, args, {
            cwd: process.cwd(),
            maxBuffer: 1024 * 1024,
            ...options
        });

        return stdout.trim();
    } catch {
        return null;
    }
}

async function collectEnvironment({
    apiUrl,
    batchSizes,
    warmupAttempts,
    registeredContext,
    credential,
    gitStatusShort
}) {
    return {
        evaluationTimestamp: new Date().toISOString(),
        nodeVersion: process.version,
        platform: `${os.type()} ${os.release()} ${os.arch()}`,
        fabricChannel: process.env.FABRIC_CHANNEL_NAME || "mychannel",
        fabricChaincode:
            process.env.FABRIC_CHAINCODE_NAME || "identityregistry",
        fabricChaincodeVersionSequence:
            await commandOrNull("peer", [
                "lifecycle",
                "chaincode",
                "querycommitted",
                "--channelID",
                process.env.FABRIC_CHANNEL_NAME || "mychannel",
                "--name",
                process.env.FABRIC_CHAINCODE_NAME || "identityregistry"
            ]),
        apiEndpoint: apiUrl,
        simulationModeRequired: true,
        simulationModeVerifiedByWarmup: false,
        batchSizes,
        warmupAttempts,
        primaryDeviceDid: credential.did,
        primaryDeviceDirectory: credential.directory,
        registeredContext,
        gitStatusShort
    };
}

async function runWarmup({
    apiUrl,
    credential,
    registeredContext,
    warmupAttempts
}) {
    const scenario = {
        name: "WARMUP_LEGITIMATE",
        expectedDecision: "GRANTED",
        expectedSpoofingClassification: "NONE",
        expectedHttpStatus: 200,
        simulatedMacAddress: registeredContext.registeredMacAddress,
        simulatedIpAddress: registeredContext.registeredIpAddress
    };
    const warmups = [];

    for (let iteration = 1; iteration <= warmupAttempts; iteration += 1) {
        const result = await runSignedScenario({
            apiUrl,
            credential,
            scenario,
            iteration,
            batchSize: 0
        });

        result.warmup = true;
        warmups.push(result);

        if (
            result.actualDecision !== "GRANTED" ||
            result.actualClassification !== "NONE" ||
            result.httpStatus !== 200
        ) {
            throw new Error(
                "Warm-up legitimate authentication failed; confirm ALLOW_SIMULATED_NETWORK_CONTEXT=true"
            );
        }
    }

    await correlateAuditEvents(apiUrl, warmups);

    return warmups;
}

async function verifyAuditEvent(apiUrl, eventId) {
    if (!eventId) {
        return false;
    }

    const response = await requestJson(
        apiUrl,
        `/api/audit/authentication/${encodeURIComponent(eventId)}`
    );

    return response.ok &&
        response.body?.success === true &&
        response.body?.data?.eventId === eventId;
}

function auditMatrixEntry({
    scenario,
    finalDecision,
    auditExpected,
    auditFound,
    auditEventId,
    cause
}) {
    return {
        scenario,
        finalApiDecision: finalDecision,
        auditEventExpected: auditExpected,
        auditEventFound: auditFound,
        auditEventId: auditEventId || null,
        cause
    };
}

async function runExpiredChallengeAuditProbe({
    apiUrl,
    credential,
    registeredContext,
    skipped
}) {
    if (skipped) {
        return auditMatrixEntry({
            scenario: "EXPIRED challenge",
            finalDecision: "SKIPPED",
            auditExpected: true,
            auditFound: false,
            cause: "Skipped by --skip-expired-audit-check"
        });
    }

    const scenario = {
        name: "EXPIRED_CHALLENGE",
        simulatedMacAddress: registeredContext.registeredMacAddress,
        simulatedIpAddress: registeredContext.registeredIpAddress
    };
    const challengeResponse = await requestChallenge(apiUrl, credential.did);
    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        return auditMatrixEntry({
            scenario: "EXPIRED challenge",
            finalDecision: responseDecision(challengeResponse),
            auditExpected: true,
            auditFound: false,
            cause: "Challenge request failed before expiration probe"
        });
    }

    const waitMs = Math.max(
        0,
        Date.parse(challenge.expiresAt) - Date.now() +
            EXPIRED_CHALLENGE_GRACE_MS
    );

    console.warn(
        `Waiting ${waitMs} ms for one expired-challenge audit probe`
    );
    await sleep(waitMs);

    const signed = signChallengePayload(
        credential.privateKey,
        challenge.challengePayload
    );
    const verification = await submitVerification(apiUrl, scenario, {
        did: credential.did,
        challengeId: challenge.challengeId,
        signature: signed.signature
    });
    const auditEventId = verification.body?.auditEventId || null;

    return auditMatrixEntry({
        scenario: "EXPIRED challenge",
        finalDecision: responseDecision(verification),
        auditExpected: true,
        auditFound: await verifyAuditEvent(apiUrl, auditEventId),
        auditEventId,
        cause: "Expired challenge is rejected in /api/auth/verify and audited as EXPIRED_CHALLENGE"
    });
}

async function runUnknownChallengeAuditProbe({
    apiUrl,
    credential,
    registeredContext
}) {
    const scenario = {
        name: "UNKNOWN_CHALLENGE",
        simulatedMacAddress: registeredContext.registeredMacAddress,
        simulatedIpAddress: registeredContext.registeredIpAddress
    };
    const verification = await submitVerification(apiUrl, scenario, {
        did: credential.did,
        challengeId: crypto.randomUUID(),
        signature: Buffer.from("unknown-challenge-proof").toString("base64")
    });
    const auditEventId = verification.body?.auditEventId || null;

    return auditMatrixEntry({
        scenario: "UNKNOWN challenge",
        finalDecision: responseDecision(verification),
        auditExpected: true,
        auditFound: await verifyAuditEvent(apiUrl, auditEventId),
        auditEventId,
        cause: "Unknown valid-format challenge ID reaches /api/auth/verify and is audited as INVALID_CHALLENGE"
    });
}

async function buildAuditCompletenessInvestigation({
    apiUrl,
    results,
    credential,
    registeredContext,
    skipExpiredAuditCheck
}) {
    const matrix = [];

    for (const scenarioName of [
        "LEGITIMATE",
        "MAC_SPOOF",
        "IP_SPOOF",
        "MAC_IP_SPOOF",
        "INVALID_SIGNATURE"
    ]) {
        const result = results.find((entry) =>
            entry.scenario === scenarioName
        );

        matrix.push(auditMatrixEntry({
            scenario: scenarioName,
            finalDecision: result?.actualDecision || "NOT_RUN",
            auditExpected: true,
            auditFound: Boolean(result?.auditConfirmed),
            auditEventId: result?.auditEventId || null,
            cause: "Verification endpoint records authentication outcomes"
        }));
    }

    const replay = results.find((entry) => entry.scenario === "REPLAY");

    matrix.push(auditMatrixEntry({
        scenario: "REPLAY first request",
        finalDecision: replay?.replay?.firstDecision || "NOT_RUN",
        auditExpected: true,
        auditFound: replay?.replay?.firstAuditEventId
            ? await verifyAuditEvent(apiUrl, replay.replay.firstAuditEventId)
            : false,
        auditEventId: replay?.replay?.firstAuditEventId || null,
        cause: "First replay setup request is a valid authentication and is audited"
    }));
    matrix.push(auditMatrixEntry({
        scenario: "REPLAY reused request",
        finalDecision: replay?.replay?.secondDecision || "NOT_RUN",
        auditExpected: true,
        auditFound: replay?.replay?.secondAuditEventId
            ? await verifyAuditEvent(apiUrl, replay.replay.secondAuditEventId)
            : false,
        auditEventId: replay?.replay?.secondAuditEventId || null,
        cause: "Consumed challenge replay reaches /api/auth/verify and is audited as INVALID_CHALLENGE"
    }));

    for (const scenarioName of ["SUSPENDED", "REVOKED"]) {
        const result = results.find((entry) =>
            entry.scenario === scenarioName
        );

        matrix.push(auditMatrixEntry({
            scenario: scenarioName,
            finalDecision: result?.actualDecision || "NOT_RUN",
            auditExpected: false,
            auditFound: Boolean(result?.auditConfirmed),
            auditEventId: result?.auditEventId || null,
            cause: "Challenge endpoint rejects inactive devices before a verification attempt exists"
        }));
    }

    matrix.push(await runExpiredChallengeAuditProbe({
        apiUrl,
        credential,
        registeredContext,
        skipped: skipExpiredAuditCheck
    }));
    matrix.push(await runUnknownChallengeAuditProbe({
        apiUrl,
        credential,
        registeredContext
    }));

    const expectedCount = matrix.filter((entry) =>
        entry.auditEventExpected
    ).length;
    const foundCount = matrix.filter((entry) =>
        entry.auditEventExpected && entry.auditEventFound
    ).length;

    return {
        matrix,
        expectedAuditableOutcomes: expectedCount,
        foundAuditableOutcomes: foundCount,
        completenessPercent:
            expectedCount === 0
                ? null
                : roundNumber((foundCount / expectedCount) * 100, 2),
        finding:
            "Verification outcomes are audited. SUSPENDED and REVOKED attempts are denied during challenge creation, before /api/auth/verify, so they do not produce authentication audit events in the current design.",
        phase6Observation:
            "The 40 functional scenario count and 35 auditable events can occur because status challenge rejections are not audit events while replay performs two verification submissions inside one functional scenario."
    };
}

async function main() {
    if (hasFlag("help")) {
        console.log(usage());
        return;
    }

    const apiUrl = getArg("api") || DEFAULT_API_URL;
    const deviceDirectory = getArg("device") || DEFAULT_DEVICE_DIRECTORY;
    const batchSizes = parseBatchSizes(getArg("batches"));
    const warmupAttempts = parsePositiveInteger(
        getArg("warmup"),
        DEFAULT_WARMUP_ATTEMPTS,
        "warmup"
    );
    const resultsDir = absoluteFromCwd(
        getArg("results-dir") || DEFAULT_RESULTS_DIR
    );
    const timestamp = new Date()
        .toISOString()
        .replace(TIMESTAMP_SAFE_PATTERN, "-");
    const credential = await loadDeviceCredential(deviceDirectory);

    requireDid(credential);
    await checkResultsWritable(resultsDir);

    const gitStatusShort = await commandOrNull("git", ["status", "--short"]);
    const health = await checkHealth(apiUrl);
    const primaryDeviceRecord = await getDeviceRecord(apiUrl, credential.did);
    const status = String(primaryDeviceRecord.status || "").toUpperCase();

    if (status !== "ACTIVE") {
        throw new Error(`Primary evaluation device is ${status}, not ACTIVE`);
    }

    const registeredContext = validateRegisteredContext(primaryDeviceRecord);

    if (
        registeredContext.registeredMacAddress !== "AA:BB:CC:DD:EE:01" ||
        registeredContext.registeredIpAddress !== "192.168.1.30"
    ) {
        throw new Error(
            "Primary device registered MAC/IP context does not match Phase 8 requirements"
        );
    }

    await checkAuditApi(apiUrl);

    const environment = await collectEnvironment({
        apiUrl,
        batchSizes,
        warmupAttempts,
        registeredContext,
        credential,
        gitStatusShort
    });

    const warmupResults = await runWarmup({
        apiUrl,
        credential,
        registeredContext,
        warmupAttempts
    });

    environment.simulationModeVerifiedByWarmup = true;

    const scenarios = buildScenarios({
        ...registeredContext,
        includeSuspended: true,
        includeRevoked: true
    });
    const {
        suspendedTarget,
        revokedTarget
    } = await findStatusTargets({
        apiUrl,
        credential,
        suspendedDeviceDirectory: getArg("suspended-device"),
        revokedDeviceDirectory: getArg("revoked-device")
    });

    const outputFiles = [];
    const batchReports = [];
    const allResults = [];

    console.log(JSON.stringify({
        preRunChecks: {
            health: health.body,
            primaryDeviceStatus: status,
            auditApiReachable: true,
            simulationModeVerifiedByWarmup: true,
            privateKeyExistsLocally: true,
            resultsDirectoryWritable: true,
            gitStatusShort
        },
        statusTargets: {
            suspendedDeviceDid: suspendedTarget?.did || null,
            revokedDeviceDid: revokedTarget?.did || null
        },
        warmup: {
            attempts: warmupResults.length,
            excludedFromFinalStatistics: true,
            passed: warmupResults.every((result) => result.testPassed)
        }
    }, null, 2));

    for (const batchSize of batchSizes) {
        const { batchReport, outputPath } = await runBatch({
            apiUrl,
            credential,
            scenarios,
            batchSize,
            timestamp,
            resultsDir,
            suspendedTarget,
            revokedTarget,
            environment
        });

        outputFiles.push(outputPath);
        batchReports.push(batchReport);
        allResults.push(...batchReport.results);

        if (batchReport.summary.failed > 0) {
            throw new Error(
                `Stopping after ${batchSize}-iteration batch because ${batchReport.summary.failed} tests failed`
            );
        }
    }

    const auditInvestigation =
        await buildAuditCompletenessInvestigation({
            apiUrl,
            results: allResults,
            credential,
            registeredContext,
            skipExpiredAuditCheck: hasFlag("skip-expired-audit-check")
        });
    const batchSummaries = batchReports.map((report) => ({
        batchSize: report.batchSize,
        summary: report.summary,
        auditCorrelation: {
            checked: report.auditCorrelation.checked,
            confirmed: report.auditCorrelation.confirmed
        },
        cleanup: report.cleanup
    }));
    const finalSummary = buildFinalSummary({
        timestamp: new Date().toISOString(),
        environment,
        batchSizes,
        results: allResults,
        batchSummaries,
        auditInvestigation,
        limitations: [
            "Sequential controlled batches measure consistency, not load capacity or broad network representativeness.",
            "Internal Fabric GetDevice, signature-verification, and audit-commit timings were not instrumented; verificationDurationMs is measured externally around /api/auth/verify.",
            "Warm-up observations are recorded separately in console output and excluded from final statistics."
        ]
    });
    const summaryOutputs = await writeSummaryResults({
        resultsDir,
        timestamp,
        summary: finalSummary,
        observations: allResults
    });

    console.log(JSON.stringify({
        outputFiles: [
            ...outputFiles,
            summaryOutputs.summaryPath,
            summaryOutputs.csvPath
        ],
        finalSummary
    }, null, 2));
}

main().catch((error) => {
    console.error(`Phase 8 evaluation failed: ${error.message}`);
    process.exit(1);
});
