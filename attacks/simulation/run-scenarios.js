#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const {
    SCENARIO_NAMES,
    buildScenarios
} = require("./scenarios");

const {
    summarizeResults
} = require("./metrics");

const DEFAULT_API_URL = "http://localhost:3000";
const DEFAULT_RESULTS_DIR = path.resolve(
    __dirname,
    "..",
    "results"
);
const MAX_ITERATIONS = 100;

function getArgument(name) {
    const index = process.argv.indexOf(`--${name}`);

    if (index === -1 || index + 1 >= process.argv.length) {
        return null;
    }

    return process.argv[index + 1];
}

function hasFlag(name) {
    return process.argv.includes(`--${name}`);
}

function usage() {
    return [
        "Usage:",
        "  node attacks/simulation/run-scenarios.js \\",
        "    --api http://localhost:3000 \\",
        "    --device gateway/device-client/devices/<device-folder> \\",
        "    --iterations 1",
        "",
        "Optional:",
        "  --suspended-device gateway/device-client/devices/<folder>",
        "  --revoked-device gateway/device-client/devices/<folder>",
        "  --results-dir attacks/results",
        "  --skip-status-scenarios"
    ].join("\n");
}

function parseIterations(value) {
    if (value === null) {
        return 1;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < 1 ||
        parsed > MAX_ITERATIONS
    ) {
        throw new Error(
            `--iterations must be an integer between 1 and ${MAX_ITERATIONS}`
        );
    }

    return parsed;
}

function hrtimeMs(start) {
    return Number(process.hrtime.bigint() - start) / 1_000_000;
}

function roundDuration(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        return null;
    }

    return Number(value.toFixed(3));
}

function joinApiUrl(apiUrl, routePath) {
    return new URL(routePath, apiUrl.endsWith("/")
        ? apiUrl
        : `${apiUrl}/`).toString();
}

async function readJsonFile(filePath, description) {
    let fileContents;

    try {
        fileContents = await fs.readFile(filePath, "utf8");
    } catch (error) {
        if (error.code === "ENOENT") {
            throw new Error(`${description} was not found at ${filePath}`);
        }

        throw new Error(
            `Unable to read ${description} at ${filePath}: ${error.message}`
        );
    }

    try {
        return JSON.parse(fileContents);
    } catch (error) {
        throw new Error(`${description} is not valid JSON: ${error.message}`);
    }
}

async function readTextFile(filePath, description) {
    try {
        return await fs.readFile(filePath, "utf8");
    } catch (error) {
        if (error.code === "ENOENT") {
            throw new Error(`${description} was not found at ${filePath}`);
        }

        throw new Error(
            `Unable to read ${description} at ${filePath}: ${error.message}`
        );
    }
}

function requireDid(identity, deviceDirectory) {
    if (
        typeof identity.did !== "string" ||
        identity.did.trim() === ""
    ) {
        throw new Error(`DID is missing from ${deviceDirectory}/identity.json`);
    }

    return identity.did.trim();
}

async function loadDeviceCredential(deviceDirectory) {
    const resolvedDirectory = path.resolve(process.cwd(), deviceDirectory);
    const identityPath = path.join(resolvedDirectory, "identity.json");
    const privateKeyPath = path.join(resolvedDirectory, "private-key.pem");
    const identity = await readJsonFile(identityPath, "identity.json");
    const privateKey = await readTextFile(
        privateKeyPath,
        "private-key.pem"
    );

    return {
        directory: resolvedDirectory,
        identity,
        did: requireDid(identity, resolvedDirectory),
        privateKey
    };
}

async function loadDeviceIdentity(deviceDirectory) {
    const resolvedDirectory = path.resolve(process.cwd(), deviceDirectory);
    const identityPath = path.join(resolvedDirectory, "identity.json");
    const identity = await readJsonFile(identityPath, "identity.json");

    return {
        directory: resolvedDirectory,
        identity,
        did: requireDid(identity, resolvedDirectory)
    };
}

async function requestJson(apiUrl, routePath, {
    method = "GET",
    body,
    headers = {}
} = {}) {
    const start = process.hrtime.bigint();
    const response = await fetch(
        joinApiUrl(apiUrl, routePath),
        {
            method,
            headers: body
                ? {
                    "Content-Type": "application/json",
                    ...headers
                }
                : headers,
            body: body ? JSON.stringify(body) : undefined
        }
    );
    const durationMs = roundDuration(hrtimeMs(start));
    let responseBody = null;

    try {
        responseBody = await response.json();
    } catch {
        responseBody = null;
    }

    return {
        statusCode: response.status,
        ok: response.ok,
        body: responseBody,
        durationMs
    };
}

async function getDeviceRecord(apiUrl, did) {
    const response = await requestJson(
        apiUrl,
        `/api/devices/${encodeURIComponent(did)}`
    );

    if (!response.ok || !response.body?.success) {
        throw new Error(
            `Unable to read device ${did} from API; HTTP ${response.statusCode}`
        );
    }

    return response.body.data;
}

async function requestChallenge(apiUrl, did) {
    return requestJson(
        apiUrl,
        "/api/auth/challenge",
        {
            method: "POST",
            body: {
                did
            }
        }
    );
}

function validateChallenge(challengeResponse, did) {
    const data = challengeResponse.body?.data;

    if (!challengeResponse.ok || !challengeResponse.body?.success || !data) {
        return null;
    }

    if (
        typeof data.challengeId !== "string" ||
        typeof data.challengePayload !== "string"
    ) {
        return null;
    }

    const payloadParts = data.challengePayload.split("|");

    if (
        payloadParts.length !== 4 ||
        payloadParts[0] !== did ||
        payloadParts[1] !== data.challengeId
    ) {
        return null;
    }

    return data;
}

function signChallengePayload(privateKey, challengePayload) {
    const signer = crypto.createSign("SHA256");
    signer.update(challengePayload);
    signer.end();

    return signer.sign(privateKey, "base64");
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
    return requestJson(
        apiUrl,
        "/api/auth/verify",
        {
            method: "POST",
            headers: buildSimulationHeaders(scenario),
            body: proof
        }
    );
}

function createBaseResult({
    scenario,
    iteration,
    did,
    timestamp = new Date().toISOString()
}) {
    return {
        scenario: scenario.name,
        iteration,
        did,
        expectedDecision: scenario.expectedDecision,
        actualDecision: null,
        expectedSpoofingClassification:
            scenario.expectedSpoofingClassification,
        actualSpoofingClassification: null,
        expectedHttpStatus: scenario.expectedHttpStatus,
        challengeRequestDurationMs: null,
        authenticationVerificationDurationMs: null,
        spoofingCheckDurationMs: null,
        totalEndToEndAuthenticationDurationMs: null,
        httpStatus: null,
        testPassed: false,
        timestamp
    };
}

function extractAuditEventIds(...responses) {
    return responses
        .map((response) => response?.body?.auditEventId)
        .filter((eventId) => typeof eventId === "string" && eventId !== "");
}

function responseDecision(response) {
    return response.body?.decision ||
        (response.ok ? "GRANTED" : "DENIED");
}

function responseClassification(response) {
    return response.body?.spoofingClassification || "NOT_EVALUATED";
}

function scenarioMatchesExpectation(result) {
    return (
        result.actualDecision === result.expectedDecision &&
        result.actualSpoofingClassification ===
            result.expectedSpoofingClassification &&
        result.httpStatus === result.expectedHttpStatus
    );
}

async function runSignedScenario({
    apiUrl,
    credential,
    scenario,
    iteration
}) {
    const totalStart = process.hrtime.bigint();
    const result = createBaseResult({
        scenario,
        iteration,
        did: credential.did
    });
    const challengeResponse = await requestChallenge(apiUrl, credential.did);
    result.challengeRequestDurationMs = challengeResponse.durationMs;

    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        result.httpStatus = challengeResponse.statusCode;
        result.actualDecision = responseDecision(challengeResponse);
        result.actualSpoofingClassification =
            responseClassification(challengeResponse);
        result.reason = challengeResponse.body?.message ||
            challengeResponse.body?.reason ||
            "Challenge request failed";
        result.totalEndToEndAuthenticationDurationMs =
            roundDuration(hrtimeMs(totalStart));
        result.testPassed = scenarioMatchesExpectation(result);

        return result;
    }

    const signature = scenario.invalidSignature
        ? Buffer.from("intentionally-invalid-signature").toString("base64")
        : signChallengePayload(credential.privateKey, challenge.challengePayload);
    const verificationResponse = await submitVerification(
        apiUrl,
        scenario,
        {
            did: credential.did,
            challengeId: challenge.challengeId,
            signature
        }
    );

    result.authenticationVerificationDurationMs =
        verificationResponse.durationMs;
    result.httpStatus = verificationResponse.statusCode;
    result.actualDecision = responseDecision(verificationResponse);
    result.actualSpoofingClassification =
        responseClassification(verificationResponse);
    result.spoofingCheckDurationMs =
        verificationResponse.body?.spoofingCheckDurationMs ?? null;
    result.totalEndToEndAuthenticationDurationMs =
        roundDuration(hrtimeMs(totalStart));
    result.reason = verificationResponse.body?.reason || null;
    result.auditEventId = verificationResponse.body?.auditEventId || null;
    result.testPassed = scenarioMatchesExpectation(result);

    return result;
}

async function runReplayScenario({
    apiUrl,
    credential,
    scenario,
    iteration
}) {
    const totalStart = process.hrtime.bigint();
    const result = createBaseResult({
        scenario,
        iteration,
        did: credential.did
    });
    const challengeResponse = await requestChallenge(apiUrl, credential.did);
    result.challengeRequestDurationMs = challengeResponse.durationMs;

    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        result.httpStatus = challengeResponse.statusCode;
        result.actualDecision = responseDecision(challengeResponse);
        result.actualSpoofingClassification =
            responseClassification(challengeResponse);
        result.reason = challengeResponse.body?.message ||
            challengeResponse.body?.reason ||
            "Challenge request failed";
        result.totalEndToEndAuthenticationDurationMs =
            roundDuration(hrtimeMs(totalStart));

        return result;
    }

    const signature = signChallengePayload(
        credential.privateKey,
        challenge.challengePayload
    );
    const proof = {
        did: credential.did,
        challengeId: challenge.challengeId,
        signature
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

    const firstDecision = responseDecision(firstVerification);
    const secondDecision = responseDecision(secondVerification);
    const firstClassification = responseClassification(firstVerification);
    const secondClassification = responseClassification(secondVerification);

    result.authenticationVerificationDurationMs =
        secondVerification.durationMs;
    result.initialVerificationDurationMs = firstVerification.durationMs;
    result.replayVerificationDurationMs = secondVerification.durationMs;
    result.httpStatus = secondVerification.statusCode;
    result.actualDecision = secondDecision;
    result.actualSpoofingClassification = secondClassification;
    result.spoofingCheckDurationMs =
        secondVerification.body?.spoofingCheckDurationMs ?? null;
    result.totalEndToEndAuthenticationDurationMs =
        roundDuration(hrtimeMs(totalStart));
    result.reason = secondVerification.body?.reason || null;
    result.auditEventIds = extractAuditEventIds(
        firstVerification,
        secondVerification
    );
    result.replay = {
        challengeId: challenge.challengeId,
        firstHttpStatus: firstVerification.statusCode,
        firstDecision,
        firstSpoofingClassification: firstClassification,
        firstAuditEventId: firstVerification.body?.auditEventId || null,
        secondHttpStatus: secondVerification.statusCode,
        secondDecision,
        secondSpoofingClassification: secondClassification,
        secondAuditEventId: secondVerification.body?.auditEventId || null
    };
    result.testPassed =
        firstVerification.statusCode === 200 &&
        firstDecision === scenario.replayExpectedFirstDecision &&
        firstClassification ===
            scenario.replayExpectedFirstSpoofingClassification &&
        scenarioMatchesExpectation(result);

    return result;
}

async function runStatusScenario({
    apiUrl,
    scenario,
    target,
    iteration
}) {
    const did = target?.did || null;
    const result = createBaseResult({
        scenario,
        iteration,
        did
    });

    if (!target) {
        result.skipped = true;
        result.reason = `No ${scenario.statusScenario} test identity found`;

        return result;
    }

    const totalStart = process.hrtime.bigint();
    const challengeResponse = await requestChallenge(apiUrl, target.did);

    result.challengeRequestDurationMs = challengeResponse.durationMs;
    result.httpStatus = challengeResponse.statusCode;
    result.actualDecision = responseDecision(challengeResponse);
    result.actualSpoofingClassification =
        responseClassification(challengeResponse);
    result.reason = challengeResponse.body?.message ||
        challengeResponse.body?.reason ||
        null;
    result.totalEndToEndAuthenticationDurationMs =
        roundDuration(hrtimeMs(totalStart));
    result.testPassed = (
        result.actualDecision === scenario.expectedDecision &&
        result.httpStatus === scenario.expectedHttpStatus
    );

    return result;
}

async function patchDeviceStatus(apiUrl, did, action, body) {
    return requestJson(
        apiUrl,
        `/api/devices/${encodeURIComponent(did)}/${action}`,
        {
            method: "PATCH",
            body
        }
    );
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
            // Ignore directories without usable local identity metadata.
        }
    }

    return candidates;
}

function textIncludesSuspend(value) {
    return String(value || "").toLowerCase().includes("suspend");
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
            const record = await getDeviceRecord(apiUrl, candidate.did);
            enrichedCandidates.push({
                ...candidate,
                record,
                status: String(record.status || "").toUpperCase()
            });
        } catch {
            // The local device may not exist on the current ledger.
        }
    }

    let suspendedTarget = null;
    let revokedTarget = null;

    if (suspendedDeviceDirectory) {
        const identity = await loadDeviceIdentity(suspendedDeviceDirectory);
        const record = await getDeviceRecord(apiUrl, identity.did);
        suspendedTarget = {
            ...identity,
            record,
            status: String(record.status || "").toUpperCase()
        };
    } else {
        suspendedTarget = enrichedCandidates.find((candidate) =>
            candidate.status !== "REVOKED" &&
            (
                textIncludesSuspend(candidate.identity.owner) ||
                textIncludesSuspend(candidate.record.owner)
            )
        ) || null;
    }

    if (revokedDeviceDirectory) {
        const identity = await loadDeviceIdentity(revokedDeviceDirectory);
        const record = await getDeviceRecord(apiUrl, identity.did);
        revokedTarget = {
            ...identity,
            record,
            status: String(record.status || "").toUpperCase()
        };
    } else {
        revokedTarget = enrichedCandidates.find((candidate) =>
            candidate.status === "REVOKED"
        ) || null;
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
    scenario
}) {
    const results = [];

    if (!suspendedTarget) {
        for (let iteration = 1; iteration <= iterations; iteration += 1) {
            results.push(await runStatusScenario({
                apiUrl,
                scenario,
                target: null,
                iteration
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

    const originalStatus = suspendedTarget.status;
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
                    reason: "Phase 6 controlled attack simulation"
                }
            );

            cleanup.attempted = true;

            if (!suspendResponse.ok) {
                throw new Error(
                    `Unable to suspend test identity ${suspendedTarget.did}; HTTP ${suspendResponse.statusCode}`
                );
            }

            cleanup.temporarilySuspended = true;
        }

        for (let iteration = 1; iteration <= iterations; iteration += 1) {
            results.push(await runStatusScenario({
                apiUrl,
                scenario,
                target: suspendedTarget,
                iteration
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
    const checkedEvents = [];

    for (const eventId of eventIds) {
        const response = await requestJson(
            apiUrl,
            `/api/audit/authentication/${encodeURIComponent(eventId)}`
        );

        checkedEvents.push({
            eventId,
            httpStatus: response.statusCode,
            confirmed: response.ok &&
                response.body?.success === true &&
                response.body?.data?.eventId === eventId,
            decision: response.body?.data?.decision || null,
            spoofingClassification:
                response.body?.data?.spoofingClassification || null
        });
    }

    return {
        checked: checkedEvents.length,
        confirmed: checkedEvents.filter((event) => event.confirmed).length,
        events: checkedEvents
    };
}

async function writeResultFiles({
    resultsDir,
    report
}) {
    await fs.mkdir(resultsDir, {
        recursive: true
    });

    const timestamp = new Date()
        .toISOString()
        .replace(/[:.]/g, "-");
    const resultsPath = path.join(
        resultsDir,
        `${timestamp}-simulation-results.json`
    );
    const summaryPath = path.join(
        resultsDir,
        `${timestamp}-simulation-summary.json`
    );

    await fs.writeFile(
        resultsPath,
        `${JSON.stringify(report, null, 2)}\n`,
        "utf8"
    );
    await fs.writeFile(
        summaryPath,
        `${JSON.stringify(report.summary, null, 2)}\n`,
        "utf8"
    );

    return {
        resultsPath,
        summaryPath
    };
}

function validateRegisteredContext(deviceRecord) {
    const registeredMacAddress = deviceRecord?.registeredMacAddress;
    const registeredIpAddress = deviceRecord?.registeredIpAddress;

    if (
        typeof registeredMacAddress !== "string" ||
        registeredMacAddress.trim() === "" ||
        typeof registeredIpAddress !== "string" ||
        registeredIpAddress.trim() === ""
    ) {
        throw new Error(
            "Device record is missing registered MAC/IP context"
        );
    }

    return {
        registeredMacAddress: registeredMacAddress.trim(),
        registeredIpAddress: registeredIpAddress.trim()
    };
}

async function main() {
    const deviceDirectory = getArgument("device");

    if (!deviceDirectory) {
        throw new Error(`${usage()}\n\n--device is required`);
    }

    const apiUrl = getArgument("api") || DEFAULT_API_URL;
    const iterations = parseIterations(getArgument("iterations"));
    const resultsDir = path.resolve(
        process.cwd(),
        getArgument("results-dir") || DEFAULT_RESULTS_DIR
    );
    const includeStatusScenarios = !hasFlag("skip-status-scenarios");
    const credential = await loadDeviceCredential(deviceDirectory);
    const primaryDeviceRecord = await getDeviceRecord(apiUrl, credential.did);
    const registeredContext = validateRegisteredContext(
        primaryDeviceRecord
    );
    const scenarios = buildScenarios({
        ...registeredContext,
        includeSuspended: includeStatusScenarios,
        includeRevoked: includeStatusScenarios
    });
    const {
        suspendedTarget,
        revokedTarget
    } = includeStatusScenarios
        ? await findStatusTargets({
            apiUrl,
            credential,
            suspendedDeviceDirectory: getArgument("suspended-device"),
            revokedDeviceDirectory: getArgument("revoked-device")
        })
        : {
            suspendedTarget: null,
            revokedTarget: null
        };
    const results = [];
    const cleanup = {
        suspendedDevice: null
    };

    console.warn(
        "Phase 6 attack simulator: run only against the local project API."
    );
    console.warn(
        "Network-context spoofing scenarios require ALLOW_SIMULATED_NETWORK_CONTEXT=true on the backend."
    );

    for (let iteration = 1; iteration <= iterations; iteration += 1) {
        for (const scenario of scenarios) {
            if (scenario.name === SCENARIO_NAMES.SUSPENDED) {
                continue;
            }

            if (scenario.name === SCENARIO_NAMES.REVOKED) {
                results.push(await runStatusScenario({
                    apiUrl,
                    scenario,
                    target: revokedTarget,
                    iteration
                }));
                continue;
            }

            if (scenario.replay) {
                results.push(await runReplayScenario({
                    apiUrl,
                    credential,
                    scenario,
                    iteration
                }));
                continue;
            }

            results.push(await runSignedScenario({
                apiUrl,
                credential,
                scenario,
                iteration
            }));
        }
    }

    const suspendedScenario = scenarios.find(
        (scenario) => scenario.name === SCENARIO_NAMES.SUSPENDED
    );

    if (suspendedScenario) {
        const suspendedRun = await runWithTemporarySuspension({
            apiUrl,
            suspendedTarget,
            iterations,
            scenario: suspendedScenario
        });

        results.push(...suspendedRun.results);
        cleanup.suspendedDevice = suspendedRun.cleanup;
    }

    const firstLegitimateFailure = results.find((result) =>
        result.scenario === SCENARIO_NAMES.LEGITIMATE &&
        !result.testPassed &&
        (
            result.actualSpoofingClassification === "IP_MISMATCH" ||
            result.actualSpoofingClassification === "MAC_MISMATCH" ||
            result.actualSpoofingClassification === "MAC_AND_IP_MISMATCH"
        )
    );

    if (firstLegitimateFailure) {
        console.warn(
            "WARNING: legitimate simulated context was denied as a network-context mismatch. Backend simulation mode may be disabled."
        );
    }

    const auditCorrelation = await correlateAuditEvents(apiUrl, results);
    const summary = summarizeResults(results);
    const report = {
        metadata: {
            generatedAt: new Date().toISOString(),
            apiUrl,
            iterations,
            primaryDeviceDid: credential.did,
            primaryDeviceDirectory: credential.directory,
            registeredContext,
            simulationModeRequired: true,
            formulas: {
                detectionAccuracyPercent:
                    "true positives / (true positives + false negatives) * 100, over MAC_SPOOF/IP_SPOOF/MAC_IP_SPOOF only",
                falsePositiveRatePercent:
                    "legitimate false positives / legitimate authentication attempts * 100, over LEGITIMATE only",
                averageAuthenticationLatencyMs:
                    "mean totalEndToEndAuthenticationDurationMs across completed, non-skipped results",
                averageSpoofingCheckMs:
                    "mean spoofingCheckDurationMs values returned by the API; null values are excluded"
            }
        },
        summary,
        auditCorrelation,
        cleanup,
        results
    };
    const output = await writeResultFiles({
        resultsDir,
        report
    });

    console.log(JSON.stringify({
        resultsPath: output.resultsPath,
        summaryPath: output.summaryPath,
        summary,
        auditCorrelation: {
            checked: auditCorrelation.checked,
            confirmed: auditCorrelation.confirmed
        },
        cleanup
    }, null, 2));

    if (summary.failed > 0) {
        process.exitCode = 1;
    }
}

main().catch((error) => {
    console.error(`Attack simulation failed: ${error.message}`);
    process.exit(1);
});
