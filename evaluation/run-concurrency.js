#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const {
    calculateStats,
    percent,
    roundNumber
} = require("./statistics");

const DEFAULT_API_URL = "https://localhost:3443";
const DEFAULT_RESULTS_DIR = "evaluation/results";
const DEFAULT_DEVICE_DIRECTORY =
    "gateway/device-client/devices/33bad912-4914-449f-b674-7c5fba40d9d8";
const PRIMARY_DID =
    "did:fabric:b9f2e316-3d27-4a45-a044-128d760fff26";
const DEFAULT_LEVELS = [1, 10, 25, 50];
const DEFAULT_CONCURRENCY_CAP = 50;
const DEFAULT_ROUNDS = 3;
const DEFAULT_WARMUP_ATTEMPTS = 2;
const DEFAULT_TIMEOUT_MS = 30000;
const NORMAL_LOAD_TARGET_MS = 5000;
const TIMESTAMP_SAFE_PATTERN = /[:.]/g;
const CSV_COLUMNS = [
    "concurrencyLevel",
    "round",
    "requestIndex",
    "did",
    "challengeId",
    "challengeDurationMs",
    "signingDurationMs",
    "verificationDurationMs",
    "spoofingCheckDurationMs",
    "totalAuthenticationDurationMs",
    "httpStatus",
    "challengeHttpStatus",
    "verificationHttpStatus",
    "decision",
    "spoofingClassification",
    "auditEventId",
    "auditConfirmed",
    "success",
    "timeout",
    "errorCategory",
    "timestamp"
];

function usage() {
    return [
        "Usage:",
        "  node evaluation/run-concurrency.js --api https://localhost:3443 --ca backend/certs/server-cert.pem --device gateway/device-client/devices/<folder> --concurrency 50 --rounds 3",
        "",
        "Options:",
        "  --api <url>                 HTTPS API base URL, default https://localhost:3443",
        "  --ca <file>                 CA/certificate file for HTTPS verification",
        "  --device <directory>        Local primary device directory",
        "  --concurrency <number>      Maximum tested concurrency, default 50",
        "  --levels <list>             Comma-separated levels, default 1,10,25,50 up to concurrency",
        "  --rounds <number>           Controlled rounds per level, default 3",
        "  --warmup <number>           Warm-up authentications, default 2",
        "  --timeout-ms <number>       Per-request timeout, default 30000",
        "  --results-dir <directory>   Result directory, default evaluation/results",
        "  --admin-username <name>     Admin or viewer username for audit correlation",
        "  --admin-password-stdin      Read admin password from stdin",
        "  --backend-pid <pid>         Optional backend process PID for CPU/RSS sampling",
        "  --help                      Show this message",
        "",
        "Environment:",
        "  EVALUATION_ADMIN_USERNAME and EVALUATION_ADMIN_PASSWORD may be used instead of admin CLI input."
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

function parseLevels(value, concurrencyCap) {
    if (value) {
        const levels = value
            .split(",")
            .map((part) => Number(part.trim()))
            .filter((level) =>
                Number.isSafeInteger(level) &&
                level > 0 &&
                level <= DEFAULT_CONCURRENCY_CAP
            );

        if (levels.length === 0) {
            throw new Error("At least one valid concurrency level is required");
        }

        return [...new Set(levels)].sort((a, b) => a - b);
    }

    const levels = DEFAULT_LEVELS.filter((level) => level <= concurrencyCap);

    if (!levels.includes(concurrencyCap)) {
        levels.push(concurrencyCap);
    }

    return [...new Set(levels)].sort((a, b) => a - b);
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

function normalizeApiUrl(apiUrl) {
    return String(apiUrl || DEFAULT_API_URL).replace(/\/$/, "");
}

function sha256Hex(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

async function readJsonFile(filePath) {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function readTextFile(filePath) {
    return fs.readFile(filePath, "utf8");
}

async function readTrustedCa(caPath) {
    if (!caPath) {
        return null;
    }

    return fs.readFile(absoluteFromCwd(caPath), "utf8");
}

async function readPasswordFromStdin() {
    const chunks = [];

    for await (const chunk of process.stdin) {
        chunks.push(Buffer.from(chunk));
    }

    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

async function loadDeviceCredential(deviceDirectory) {
    const directory = absoluteFromCwd(deviceDirectory);
    const identityPath = path.join(directory, "identity.json");
    const privateKeyPath = path.join(directory, "private-key.pem");
    const identity = await readJsonFile(identityPath);

    if (typeof identity.did !== "string" || identity.did.trim() === "") {
        throw new Error(`DID is missing from ${identityPath}`);
    }

    if (
        typeof identity.macAddress !== "string" ||
        identity.macAddress.trim() === "" ||
        typeof identity.ipAddress !== "string" ||
        identity.ipAddress.trim() === ""
    ) {
        throw new Error(
            "identity.json must include registered macAddress and ipAddress"
        );
    }

    return {
        directory,
        did: identity.did.trim(),
        macAddress: identity.macAddress.trim(),
        ipAddress: identity.ipAddress.trim(),
        privateKey: await readTextFile(privateKeyPath)
    };
}

function requestJson(apiUrl, endpoint, options = {}) {
    const url = new URL(endpoint, `${normalizeApiUrl(apiUrl)}/`);
    const transport = url.protocol === "https:" ? https : http;
    const body = options.body === undefined
        ? null
        : Buffer.from(JSON.stringify(options.body));
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };
    const start = process.hrtime.bigint();

    if (body) {
        headers["Content-Length"] = String(body.length);
    }

    return new Promise((resolve, reject) => {
        const requestOptions = {
            method: options.method || "GET",
            headers
        };

        if (url.protocol === "https:" && options.ca) {
            requestOptions.ca = options.ca;
        }

        const request = transport.request(
            url,
            requestOptions,
            (response) => {
                const chunks = [];

                response.on("data", (chunk) => {
                    chunks.push(chunk);
                });

                response.on("end", () => {
                    const rawBody = Buffer.concat(chunks).toString("utf8");
                    let parsedBody = null;

                    if (rawBody) {
                        try {
                            parsedBody = JSON.parse(rawBody);
                        } catch {
                            parsedBody = {
                                rawBody
                            };
                        }
                    }

                    resolve({
                        statusCode: response.statusCode,
                        ok: response.statusCode >= 200 &&
                            response.statusCode < 300,
                        headers: response.headers,
                        body: parsedBody,
                        durationMs: roundDuration(hrtimeMs(start))
                    });
                });
            }
        );

        request.setTimeout(options.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
            const error = new Error("Request timed out");

            error.code = "ETIMEDOUT";
            request.destroy(error);
        });

        request.on("error", (error) => {
            error.durationMs = roundDuration(hrtimeMs(start));
            reject(error);
        });

        if (body) {
            request.write(body);
        }

        request.end();
    });
}

function cookieHeaderFromSetCookie(setCookieHeaders) {
    if (!Array.isArray(setCookieHeaders)) {
        return "";
    }

    return setCookieHeaders
        .map((cookie) => cookie.split(";")[0])
        .filter(Boolean)
        .join("; ");
}

async function adminLogin({
    apiUrl,
    ca,
    timeoutMs,
    username,
    password
}) {
    const response = await requestJson(apiUrl, "/api/admin/login", {
        method: "POST",
        ca,
        timeoutMs,
        body: {
            username,
            password
        }
    });

    if (!response.ok || response.body?.success !== true) {
        throw new Error(
            `Admin login failed; HTTP ${response.statusCode}`
        );
    }

    const cookieHeader = cookieHeaderFromSetCookie(
        response.headers["set-cookie"]
    );

    if (!cookieHeader) {
        throw new Error("Admin login did not return a session cookie");
    }

    return cookieHeader;
}

async function getHealth(apiUrl, ca, timeoutMs) {
    return requestJson(apiUrl, "/api/health", {
        ca,
        timeoutMs
    });
}

async function getDeviceRecord(apiUrl, ca, timeoutMs, adminCookie, did) {
    return requestJson(
        apiUrl,
        `/api/devices/${encodeURIComponent(did)}`,
        {
            ca,
            timeoutMs,
            headers: {
                Cookie: adminCookie
            }
        }
    );
}

async function requestChallenge(apiUrl, ca, timeoutMs, did) {
    return requestJson(apiUrl, "/api/auth/challenge", {
        method: "POST",
        ca,
        timeoutMs,
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

    const parts = data.challengePayload.split("|");

    if (
        parts.length !== 4 ||
        parts[0] !== did ||
        parts[1] !== data.challengeId ||
        parts[2].trim() === "" ||
        parts[3] !== data.expiresAt
    ) {
        return null;
    }

    return {
        challengeId: data.challengeId,
        challengePayload: data.challengePayload,
        nonceHash: sha256Hex(parts[2]),
        challengePayloadHash: sha256Hex(data.challengePayload)
    };
}

function signChallengePayload(privateKey, challengePayload) {
    const start = process.hrtime.bigint();
    const signer = crypto.createSign("SHA256");

    signer.update(challengePayload);
    signer.end();

    const signature = signer.sign(privateKey, "base64");

    return {
        signature,
        signatureHash: sha256Hex(signature),
        signingDurationMs: roundDuration(hrtimeMs(start))
    };
}

function simulatedNetworkHeaders(credential) {
    return {
        "X-Simulated-Source-MAC": credential.macAddress,
        "X-Simulated-Source-IP": credential.ipAddress
    };
}

async function submitVerification({
    apiUrl,
    ca,
    timeoutMs,
    credential,
    proof
}) {
    return requestJson(apiUrl, "/api/auth/verify", {
        method: "POST",
        ca,
        timeoutMs,
        headers: simulatedNetworkHeaders(credential),
        body: proof
    });
}

function createObservation({
    concurrencyLevel,
    round,
    requestIndex,
    did
}) {
    return {
        concurrencyLevel,
        round,
        requestIndex,
        did,
        challengeId: null,
        nonceHash: null,
        challengePayloadHash: null,
        signatureHash: null,
        challengeDurationMs: null,
        signingDurationMs: null,
        verificationDurationMs: null,
        spoofingCheckDurationMs: null,
        totalAuthenticationDurationMs: null,
        httpStatus: null,
        challengeHttpStatus: null,
        verificationHttpStatus: null,
        decision: null,
        spoofingClassification: null,
        auditEventId: null,
        auditConfirmed: false,
        success: false,
        timeout: false,
        errorCategory: null,
        errorMessage: null,
        timestamp: new Date().toISOString()
    };
}

function responseDecision(response) {
    return response.body?.decision || (response.ok ? "GRANTED" : "DENIED");
}

function responseClassification(response) {
    return response.body?.spoofingClassification || "NOT_EVALUATED";
}

function categorizeError(error, fallback) {
    if (error.code === "ETIMEDOUT") {
        return "TIMEOUT";
    }

    return fallback;
}

async function runAuthenticationAttempt({
    apiUrl,
    ca,
    timeoutMs,
    credential,
    concurrencyLevel,
    round,
    requestIndex
}) {
    const totalStart = process.hrtime.bigint();
    const observation = createObservation({
        concurrencyLevel,
        round,
        requestIndex,
        did: credential.did
    });

    try {
        let challengeResponse;

        try {
            challengeResponse = await requestChallenge(
                apiUrl,
                ca,
                timeoutMs,
                credential.did
            );
        } catch (error) {
            observation.timeout = error.code === "ETIMEDOUT";
            observation.errorCategory =
                categorizeError(error, "CHALLENGE_REQUEST_FAILED");
            observation.errorMessage = error.message;
            observation.challengeDurationMs = error.durationMs;
            observation.totalAuthenticationDurationMs =
                roundDuration(hrtimeMs(totalStart));

            return observation;
        }

        observation.challengeDurationMs = challengeResponse.durationMs;
        observation.challengeHttpStatus = challengeResponse.statusCode;
        observation.httpStatus = challengeResponse.statusCode;

        const challenge = validateChallenge(
            challengeResponse,
            credential.did
        );

        if (!challenge) {
            observation.decision = responseDecision(challengeResponse);
            observation.spoofingClassification =
                responseClassification(challengeResponse);
            observation.errorCategory = "MALFORMED_OR_REJECTED_CHALLENGE";
            observation.errorMessage =
                challengeResponse.body?.message ||
                "Challenge response was rejected";
            observation.totalAuthenticationDurationMs =
                roundDuration(hrtimeMs(totalStart));

            return observation;
        }

        observation.challengeId = challenge.challengeId;
        observation.nonceHash = challenge.nonceHash;
        observation.challengePayloadHash = challenge.challengePayloadHash;

        let signed;

        try {
            signed = signChallengePayload(
                credential.privateKey,
                challenge.challengePayload
            );
        } catch (error) {
            observation.errorCategory = "SIGNING_FAILED";
            observation.errorMessage = error.message;
            observation.totalAuthenticationDurationMs =
                roundDuration(hrtimeMs(totalStart));

            return observation;
        }

        observation.signingDurationMs = signed.signingDurationMs;
        observation.signatureHash = signed.signatureHash;

        let verificationResponse;

        try {
            verificationResponse = await submitVerification({
                apiUrl,
                ca,
                timeoutMs,
                credential,
                proof: {
                    did: credential.did,
                    challengeId: challenge.challengeId,
                    signature: signed.signature
                }
            });
        } catch (error) {
            observation.timeout = error.code === "ETIMEDOUT";
            observation.errorCategory =
                categorizeError(error, "VERIFICATION_REQUEST_FAILED");
            observation.errorMessage = error.message;
            observation.verificationDurationMs = error.durationMs;
            observation.totalAuthenticationDurationMs =
                roundDuration(hrtimeMs(totalStart));

            return observation;
        }

        observation.verificationDurationMs =
            verificationResponse.durationMs;
        observation.verificationHttpStatus =
            verificationResponse.statusCode;
        observation.httpStatus = verificationResponse.statusCode;
        observation.decision = responseDecision(verificationResponse);
        observation.spoofingClassification =
            responseClassification(verificationResponse);
        observation.spoofingCheckDurationMs =
            verificationResponse.body?.spoofingCheckDurationMs ?? null;
        observation.auditEventId =
            verificationResponse.body?.auditEventId || null;
        observation.totalAuthenticationDurationMs =
            roundDuration(hrtimeMs(totalStart));
        observation.success = (
            verificationResponse.statusCode === 200 &&
            verificationResponse.body?.authenticated === true &&
            observation.decision === "GRANTED" &&
            observation.spoofingClassification === "NONE"
        );

        if (!observation.success) {
            observation.errorCategory = "AUTHENTICATION_NOT_GRANTED";
            observation.errorMessage =
                verificationResponse.body?.reason ||
                verificationResponse.body?.message ||
                "Authentication was not granted";
        }

        return observation;
    } catch (error) {
        observation.timeout = error.code === "ETIMEDOUT";
        observation.errorCategory =
            categorizeError(error, "UNEXPECTED_EXCEPTION");
        observation.errorMessage = error.message;
        observation.totalAuthenticationDurationMs =
            roundDuration(hrtimeMs(totalStart));

        return observation;
    }
}

async function fetchAuditEvents(apiUrl, ca, timeoutMs, adminCookie) {
    const response = await requestJson(
        apiUrl,
        "/api/audit/authentication",
        {
            ca,
            timeoutMs,
            headers: {
                Cookie: adminCookie
            }
        }
    );

    if (!response.ok || response.body?.success !== true) {
        throw new Error(
            `Unable to fetch audit events; HTTP ${response.statusCode}`
        );
    }

    return Array.isArray(response.body.data) ? response.body.data : [];
}

async function correlateAuditEvents({
    apiUrl,
    ca,
    timeoutMs,
    adminCookie,
    observations
}) {
    const expectedAuditEventIds = observations
        .map((observation) => observation.auditEventId)
        .filter(Boolean);

    if (expectedAuditEventIds.length === 0) {
        return {
            expectedAuditEvents: 0,
            confirmedAuditEvents: 0,
            correlationPercent: null
        };
    }

    const events = await fetchAuditEvents(apiUrl, ca, timeoutMs, adminCookie);
    const ledgerEventIds = new Set(events.map((event) => event.eventId));
    let confirmedAuditEvents = 0;

    for (const observation of observations) {
        if (
            observation.auditEventId &&
            ledgerEventIds.has(observation.auditEventId)
        ) {
            observation.auditConfirmed = true;
            confirmedAuditEvents += 1;
        }
    }

    return {
        expectedAuditEvents: expectedAuditEventIds.length,
        confirmedAuditEvents,
        correlationPercent: percent(
            confirmedAuditEvents,
            expectedAuditEventIds.length
        )
    };
}

async function runReplayProbe({
    apiUrl,
    ca,
    timeoutMs,
    credential
}) {
    const challengeResponse = await requestChallenge(
        apiUrl,
        ca,
        timeoutMs,
        credential.did
    );
    const challenge = validateChallenge(challengeResponse, credential.did);

    if (!challenge) {
        return {
            passed: false,
            reason: "Replay probe challenge was not issued"
        };
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
    const firstResponse = await submitVerification({
        apiUrl,
        ca,
        timeoutMs,
        credential,
        proof
    });

    if (
        firstResponse.statusCode !== 200 ||
        firstResponse.body?.authenticated !== true
    ) {
        return {
            passed: false,
            reason: "Initial replay probe verification was not granted",
            firstHttpStatus: firstResponse.statusCode,
            firstDecision: firstResponse.body?.decision || null
        };
    }

    const replayStart = process.hrtime.bigint();
    const replayResponse = await submitVerification({
        apiUrl,
        ca,
        timeoutMs,
        credential,
        proof
    });
    const replayDenied = (
        replayResponse.statusCode === 401 &&
        replayResponse.body?.decision === "DENIED"
    );

    return {
        passed: replayDenied,
        reason: replayDenied
            ? "Consumed challenge was rejected on replay"
            : "Consumed challenge replay was not rejected as expected",
        challengeId: challenge.challengeId,
        challengePayloadHash: challenge.challengePayloadHash,
        nonceHash: challenge.nonceHash,
        signatureHash: signed.signatureHash,
        firstAuditEventId: firstResponse.body?.auditEventId || null,
        firstHttpStatus: firstResponse.statusCode,
        firstDecision: firstResponse.body?.decision || null,
        replayHttpStatus: replayResponse.statusCode,
        replayDecision: replayResponse.body?.decision || null,
        replayDurationMs: roundDuration(hrtimeMs(replayStart))
    };
}

async function readProcessSample(pid) {
    if (!pid) {
        return null;
    }

    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    const status = await fs.readFile(`/proc/${pid}/status`, "utf8");
    const afterCommand = stat.slice(stat.lastIndexOf(")") + 2);
    const parts = afterCommand.split(" ");
    const userTicks = Number(parts[11]);
    const systemTicks = Number(parts[12]);
    const rssLine = status
        .split("\n")
        .find((line) => line.startsWith("VmRSS:"));
    const rssKb = rssLine
        ? Number(rssLine.replace(/\D+/g, " ").trim().split(" ")[0])
        : null;

    return {
        cpuTicks: userTicks + systemTicks,
        rssBytes: Number.isFinite(rssKb) ? rssKb * 1024 : null
    };
}

function resourceStart(pid) {
    return {
        sampledAt: new Date().toISOString(),
        loadAverage: os.loadavg(),
        backendPid: pid || null
    };
}

async function startResourceObservation(pid) {
    const start = resourceStart(pid);

    if (pid) {
        try {
            start.backendProcess = await readProcessSample(pid);
        } catch (error) {
            start.backendProcessError = error.message;
        }
    }

    return start;
}

async function finishResourceObservation(start, wallClockMs) {
    const finish = {
        sampledAt: new Date().toISOString(),
        loadAverage: os.loadavg()
    };

    if (!start.backendPid) {
        return {
            available: false,
            reason: "No --backend-pid was provided",
            start,
            finish
        };
    }

    if (!start.backendProcess) {
        return {
            available: false,
            reason: start.backendProcessError ||
                "Backend process could not be sampled",
            start,
            finish
        };
    }

    try {
        finish.backendProcess = await readProcessSample(start.backendPid);
    } catch (error) {
        return {
            available: false,
            reason: error.message,
            start,
            finish
        };
    }

    const clockTicksPerSecond = 100;
    const cpuTicks =
        finish.backendProcess.cpuTicks - start.backendProcess.cpuTicks;
    const cpuSeconds = cpuTicks / clockTicksPerSecond;
    const wallSeconds = wallClockMs / 1000;

    return {
        available: true,
        backendPid: start.backendPid,
        backendCpuPercent: roundNumber((cpuSeconds / wallSeconds) * 100),
        backendRssBytes: finish.backendProcess.rssBytes,
        backendRssMb: finish.backendProcess.rssBytes
            ? roundNumber(finish.backendProcess.rssBytes / 1024 / 1024)
            : null,
        cpuSamplingNote:
            "Linux /proc sampling; CPU percent uses an assumed 100 clock ticks per second.",
        start,
        finish
    };
}

function uniqueCount(values) {
    return new Set(values.filter(Boolean)).size;
}

function summarizeRound({
    concurrencyLevel,
    round,
    observations,
    wallClockMs,
    auditCorrelation
}) {
    return {
        concurrencyLevel,
        round,
        attempts: observations.length,
        wallClockMs: roundDuration(wallClockMs),
        successes: observations.filter((observation) =>
            observation.success
        ).length,
        failures: observations.filter((observation) =>
            !observation.success
        ).length,
        timeouts: observations.filter((observation) =>
            observation.timeout
        ).length,
        auditCorrelation
    };
}

function summarizeLevel({
    level,
    observations,
    rounds,
    resourceObservation
}) {
    const successfulAuthentications = observations.filter((observation) =>
        observation.success
    ).length;
    const timeoutCount = observations.filter((observation) =>
        observation.timeout
    ).length;
    const completedAuthentications = observations.filter((observation) =>
        observation.decision !== null &&
        !observation.timeout
    ).length;
    const totalRoundWallClockMs = rounds.reduce(
        (total, round) => total + round.wallClockMs,
        0
    );
    const totalLatencyStats = calculateStats(
        observations.map((observation) =>
            observation.totalAuthenticationDurationMs
        )
    );
    const challengeStats = calculateStats(
        observations.map((observation) => observation.challengeDurationMs)
    );
    const verificationStats = calculateStats(
        observations.map((observation) =>
            observation.verificationDurationMs
        )
    );
    const signingStats = calculateStats(
        observations.map((observation) => observation.signingDurationMs)
    );
    const spoofingStats = calculateStats(
        observations.map((observation) =>
            observation.spoofingCheckDurationMs
        )
    );
    const expectedAuditEvents = rounds.reduce(
        (total, round) =>
            total + (round.auditCorrelation?.expectedAuditEvents || 0),
        0
    );
    const confirmedAuditEvents = rounds.reduce(
        (total, round) =>
            total + (round.auditCorrelation?.confirmedAuditEvents || 0),
        0
    );

    return {
        concurrencyLevel: level,
        totalAttempts: observations.length,
        completedAuthentications,
        successfulAuthentications,
        failedAuthentications:
            observations.length - successfulAuthentications,
        successRatePercent: percent(
            successfulAuthentications,
            observations.length
        ),
        failureRatePercent: percent(
            observations.length - successfulAuthentications,
            observations.length
        ),
        timeoutCount,
        timeoutRatePercent: percent(timeoutCount, observations.length),
        minTotalLatencyMs: totalLatencyStats.min,
        maxTotalLatencyMs: totalLatencyStats.max,
        meanLatencyMs: totalLatencyStats.mean,
        medianLatencyMs: totalLatencyStats.median,
        standardDeviationMs: totalLatencyStats.standardDeviation,
        p95LatencyMs: totalLatencyStats.p95,
        p99LatencyMs: totalLatencyStats.p99,
        completedAuthenticationsPerSecond: totalRoundWallClockMs > 0
            ? roundNumber(
                completedAuthentications / (totalRoundWallClockMs / 1000)
            )
            : null,
        throughputPerSecond: totalRoundWallClockMs > 0
            ? roundNumber(
                completedAuthentications / (totalRoundWallClockMs / 1000)
            )
            : null,
        totalRoundWallClockMs: roundDuration(totalRoundWallClockMs),
        challengeDurationMs: challengeStats,
        signingDurationMs: signingStats,
        verificationDurationMs: verificationStats,
        spoofingCheckDurationMs: spoofingStats,
        uniqueChallengeIds: uniqueCount(
            observations.map((observation) => observation.challengeId)
        ),
        uniqueNonceHashes: uniqueCount(
            observations.map((observation) => observation.nonceHash)
        ),
        uniqueChallengePayloadHashes: uniqueCount(
            observations.map((observation) =>
                observation.challengePayloadHash
            )
        ),
        uniqueSignatureHashes: uniqueCount(
            observations.map((observation) => observation.signatureHash)
        ),
        uniqueAuditEventIds: uniqueCount(
            observations.map((observation) => observation.auditEventId)
        ),
        expectedAuditEvents,
        confirmedAuditEvents,
        auditCorrelationPercent: percent(
            confirmedAuditEvents,
            expectedAuditEvents
        ),
        rounds,
        resourceObservation
    };
}

function levelHasSeriousDefect(levelSummary) {
    return (
        levelSummary.successRatePercent !== 100 ||
        levelSummary.timeoutCount > 0 ||
        levelSummary.uniqueChallengeIds !== levelSummary.totalAttempts ||
        levelSummary.uniqueNonceHashes !== levelSummary.totalAttempts ||
        levelSummary.uniqueSignatureHashes !== levelSummary.totalAttempts ||
        levelSummary.auditCorrelationPercent !== 100
    );
}

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

function observationsToCsv(observations) {
    return [
        CSV_COLUMNS.join(","),
        ...observations.map((observation) =>
            CSV_COLUMNS
                .map((column) => csvEscape(observation[column]))
                .join(",")
        )
    ].join("\n") + "\n";
}

async function writeJson(filePath, value) {
    await fs.writeFile(
        filePath,
        `${JSON.stringify(value, null, 2)}\n`,
        "utf8"
    );
}

async function writeOutputs({
    resultsDir,
    timestamp,
    report,
    summary,
    observations
}) {
    await fs.mkdir(resultsDir, {
        recursive: true
    });

    const reportPath = path.join(resultsDir, `concurrency-${timestamp}.json`);
    const summaryPath = path.join(
        resultsDir,
        `concurrency-summary-${timestamp}.json`
    );
    const csvPath = path.join(
        resultsDir,
        `concurrency-observations-${timestamp}.csv`
    );

    await writeJson(reportPath, report);
    await writeJson(summaryPath, summary);
    await fs.writeFile(csvPath, observationsToCsv(observations), "utf8");

    return {
        reportPath,
        summaryPath,
        csvPath
    };
}

async function runWarmup({
    apiUrl,
    ca,
    timeoutMs,
    credential,
    warmupAttempts
}) {
    const warmupResults = [];

    for (let index = 1; index <= warmupAttempts; index += 1) {
        warmupResults.push(await runAuthenticationAttempt({
            apiUrl,
            ca,
            timeoutMs,
            credential,
            concurrencyLevel: 1,
            round: -1,
            requestIndex: index
        }));
    }

    return warmupResults;
}

async function runLevel({
    apiUrl,
    ca,
    timeoutMs,
    adminCookie,
    credential,
    level,
    roundsPerLevel,
    backendPid
}) {
    const resourceStartSample = await startResourceObservation(backendPid);
    const levelStart = process.hrtime.bigint();
    const observations = [];
    const rounds = [];

    for (let round = 1; round <= roundsPerLevel; round += 1) {
        const roundStart = process.hrtime.bigint();
        const settled = await Promise.allSettled(
            Array.from({
                length: level
            }, (_, index) =>
                runAuthenticationAttempt({
                    apiUrl,
                    ca,
                    timeoutMs,
                    credential,
                    concurrencyLevel: level,
                    round,
                    requestIndex: index + 1
                })
            )
        );
        const roundWallClockMs = hrtimeMs(roundStart);
        const roundObservations = settled.map((result, index) => {
            if (result.status === "fulfilled") {
                return result.value;
            }

            return {
                ...createObservation({
                    concurrencyLevel: level,
                    round,
                    requestIndex: index + 1,
                    did: credential.did
                }),
                totalAuthenticationDurationMs:
                    roundDuration(roundWallClockMs),
                errorCategory: "UNEXPECTED_REJECTION",
                errorMessage: result.reason?.message ||
                    "Promise rejected unexpectedly"
            };
        });
        let auditCorrelation;

        try {
            auditCorrelation = await correlateAuditEvents({
                apiUrl,
                ca,
                timeoutMs,
                adminCookie,
                observations: roundObservations
            });
        } catch (error) {
            auditCorrelation = {
                expectedAuditEvents: roundObservations
                    .filter((observation) => observation.auditEventId)
                    .length,
                confirmedAuditEvents: 0,
                correlationPercent: 0,
                error: error.message
            };
        }

        observations.push(...roundObservations);
        rounds.push(summarizeRound({
            concurrencyLevel: level,
            round,
            observations: roundObservations,
            wallClockMs: roundWallClockMs,
            auditCorrelation
        }));
    }

    const resourceObservation = await finishResourceObservation(
        resourceStartSample,
        hrtimeMs(levelStart)
    );

    return {
        observations,
        summary: summarizeLevel({
            level,
            observations,
            rounds,
            resourceObservation
        })
    };
}

function buildRequirement50(resultsByLevel, replayProbe) {
    const level50 = resultsByLevel["50"];

    if (!level50) {
        return {
            passed: false,
            reason: "Concurrency level 50 was not executed"
        };
    }

    const correctnessPassed =
        level50.successRatePercent === 100 &&
        level50.failedAuthentications === 0;
    const reliabilityPassed =
        level50.timeoutCount === 0 &&
        level50.completedAuthentications === level50.totalAttempts;
    const securityPassed =
        replayProbe.passed === true &&
        level50.uniqueChallengeIds === level50.totalAttempts &&
        level50.uniqueNonceHashes === level50.totalAttempts &&
        level50.uniqueSignatureHashes === level50.totalAttempts &&
        level50.uniqueAuditEventIds === level50.totalAttempts &&
        level50.auditCorrelationPercent === 100;
    const performancePassed =
        typeof level50.meanLatencyMs === "number" &&
        typeof level50.p95LatencyMs === "number" &&
        level50.meanLatencyMs <= NORMAL_LOAD_TARGET_MS &&
        level50.p95LatencyMs <= NORMAL_LOAD_TARGET_MS;
    const passed = correctnessPassed &&
        reliabilityPassed &&
        securityPassed &&
        performancePassed;

    return {
        passed,
        correctnessPassed,
        reliabilityPassed,
        securityPassed,
        performancePassed,
        normalLoadTargetMs: NORMAL_LOAD_TARGET_MS,
        normalLoadInterpretation:
            "PASS requires 100% legitimate GRANTED/NONE results, zero timeouts, unique single-use challenge/signature material, 100% audit correlation, and both mean and p95 latency at or below 5000 ms.",
        reason: passed
            ? "50 concurrent authentication flows completed correctly with no timeouts, no replay/security regression, full audit correlation, and mean/p95 latency within the 5 second target."
            : "One or more 50-concurrent correctness, reliability, security, audit, or latency criteria were not satisfied."
    };
}

function addBaselineComparisons(resultsByLevel) {
    const baseline = resultsByLevel["1"]?.meanLatencyMs;
    const comparisons = {
        phase8LegitimateMeanReferenceMs: "approximately 2100-2200",
        phase9PostChaincodeAuthenticationMeanReferenceMs:
            "approximately 2260",
        currentConcurrency1MeanMs: baseline || null,
        levels: {}
    };

    for (const [level, summary] of Object.entries(resultsByLevel)) {
        comparisons.levels[level] = {
            meanLatencyMs: summary.meanLatencyMs,
            latencyIncreasePercent: (
                typeof baseline === "number" &&
                typeof summary.meanLatencyMs === "number"
            )
                ? roundNumber(
                    ((summary.meanLatencyMs - baseline) / baseline) * 100,
                    2
                )
                : null
        };
        summary.latencyIncreaseVsConcurrency1Percent =
            comparisons.levels[level].latencyIncreasePercent;
    }

    return comparisons;
}

function compactConsoleSummary(summary) {
    const compactResults = {};

    for (const [level, result] of Object.entries(summary.results)) {
        compactResults[level] = {
            successRatePercent: result.successRatePercent,
            timeoutRatePercent: result.timeoutRatePercent,
            meanLatencyMs: result.meanLatencyMs,
            medianLatencyMs: result.medianLatencyMs,
            p95LatencyMs: result.p95LatencyMs,
            maxTotalLatencyMs: result.maxTotalLatencyMs,
            throughputPerSecond: result.throughputPerSecond,
            auditCorrelationPercent: result.auditCorrelationPercent,
            latencyIncreaseVsConcurrency1Percent:
                result.latencyIncreaseVsConcurrency1Percent
        };
    }

    return {
        evaluationDate: summary.evaluationDate,
        levels: summary.levels,
        roundsPerLevel: summary.roundsPerLevel,
        results: compactResults,
        replayProtectionProbe: summary.replayProtectionProbe,
        requirement50Concurrent: summary.requirement50Concurrent,
        outputFiles: summary.outputFiles
    };
}

async function main() {
    if (hasFlag("help")) {
        console.log(usage());
        return;
    }

    const apiUrl = normalizeApiUrl(getArg("api") || DEFAULT_API_URL);
    const caPath = getArg("ca");
    const ca = await readTrustedCa(caPath);
    const deviceDirectory =
        getArg("device") || DEFAULT_DEVICE_DIRECTORY;
    const credential = await loadDeviceCredential(deviceDirectory);
    const concurrencyCap = parsePositiveInteger(
        getArg("concurrency"),
        DEFAULT_CONCURRENCY_CAP,
        "Concurrency"
    );
    const levels = parseLevels(getArg("levels"), concurrencyCap);
    const roundsPerLevel = parsePositiveInteger(
        getArg("rounds"),
        DEFAULT_ROUNDS,
        "Rounds"
    );
    const warmupAttempts = parsePositiveInteger(
        getArg("warmup"),
        DEFAULT_WARMUP_ATTEMPTS,
        "Warm-up attempts"
    );
    const timeoutMs = parsePositiveInteger(
        getArg("timeout-ms"),
        DEFAULT_TIMEOUT_MS,
        "Timeout"
    );
    const resultsDir = absoluteFromCwd(
        getArg("results-dir") || DEFAULT_RESULTS_DIR
    );
    const backendPid = getArg("backend-pid")
        ? parsePositiveInteger(getArg("backend-pid"), null, "Backend PID")
        : null;
    const adminUsername =
        getArg("admin-username") ||
        process.env.EVALUATION_ADMIN_USERNAME;
    const adminPassword = hasFlag("admin-password-stdin")
        ? await readPasswordFromStdin()
        : process.env.EVALUATION_ADMIN_PASSWORD;

    if (credential.did !== PRIMARY_DID) {
        throw new Error(
            `Primary concurrency DID must be ${PRIMARY_DID}; found ${credential.did}`
        );
    }

    if (concurrencyCap > DEFAULT_CONCURRENCY_CAP) {
        throw new Error("Formal Phase 11 concurrency is capped at 50");
    }

    if (!apiUrl.startsWith("https://")) {
        throw new Error("Phase 11 formal concurrency tests must use HTTPS");
    }

    if (!ca) {
        throw new Error("A --ca certificate file is required for HTTPS evaluation");
    }

    if (!adminUsername || !adminPassword) {
        throw new Error(
            "Admin credentials are required for protected audit correlation"
        );
    }

    const health = await getHealth(apiUrl, ca, timeoutMs);

    if (!health.ok || health.body?.fabric !== "connected") {
        throw new Error("Fabric health check is not connected");
    }

    const adminCookie = await adminLogin({
        apiUrl,
        ca,
        timeoutMs,
        username: adminUsername,
        password: adminPassword
    });
    const deviceResponse = await getDeviceRecord(
        apiUrl,
        ca,
        timeoutMs,
        adminCookie,
        credential.did
    );
    const deviceStatus = String(
        deviceResponse.body?.data?.status || ""
    ).toUpperCase();

    if (!deviceResponse.ok || deviceStatus !== "ACTIVE") {
        throw new Error("Primary test device must remain ACTIVE");
    }

    const warmupResults = await runWarmup({
        apiUrl,
        ca,
        timeoutMs,
        credential,
        warmupAttempts
    });

    if (warmupResults.some((result) => !result.success)) {
        throw new Error("Warm-up authentication did not succeed");
    }

    const replayProbe = await runReplayProbe({
        apiUrl,
        ca,
        timeoutMs,
        credential
    });

    if (!replayProbe.passed) {
        throw new Error(replayProbe.reason);
    }

    const timestamp = new Date()
        .toISOString()
        .replace(TIMESTAMP_SAFE_PATTERN, "-");
    const observations = [];
    const resultsByLevel = {};
    let stoppedEarly = null;

    for (const level of levels) {
        const levelResult = await runLevel({
            apiUrl,
            ca,
            timeoutMs,
            adminCookie,
            credential,
            level,
            roundsPerLevel,
            backendPid
        });

        observations.push(...levelResult.observations);
        resultsByLevel[String(level)] = levelResult.summary;

        console.log(JSON.stringify({
            level,
            successRatePercent:
                levelResult.summary.successRatePercent,
            timeoutRatePercent:
                levelResult.summary.timeoutRatePercent,
            meanLatencyMs: levelResult.summary.meanLatencyMs,
            p95LatencyMs: levelResult.summary.p95LatencyMs,
            throughputPerSecond:
                levelResult.summary.throughputPerSecond,
            auditCorrelationPercent:
                levelResult.summary.auditCorrelationPercent
        }));

        if (level < 50 && levelHasSeriousDefect(levelResult.summary)) {
            stoppedEarly = {
                afterLevel: level,
                reason:
                    "Stopped before larger levels because correctness, timeout, uniqueness, or audit correlation failed."
            };
            break;
        }
    }

    const baselineComparison = addBaselineComparisons(resultsByLevel);
    const summary = {
        evaluationType: "CONCURRENT_AUTHENTICATION_CAPACITY",
        evaluationDate: new Date().toISOString(),
        apiUrl,
        tls: {
            explicitCaVerification: true,
            caPathProvided: Boolean(caPath)
        },
        device: {
            did: credential.did,
            macAddress: credential.macAddress,
            ipAddress: credential.ipAddress,
            virtualRequestModel:
                "Concurrent virtual authentication requests using one registered cryptographic test identity. Each request receives its own challenge, nonce, challengeId, signature, and audit event."
        },
        levels,
        roundsPerLevel,
        warmupAttempts,
        timeoutMs,
        normalLoadTargetMs: NORMAL_LOAD_TARGET_MS,
        results: resultsByLevel,
        baselineComparison,
        replayProtectionProbe: replayProbe,
        stoppedEarly,
        requirement50Concurrent:
            buildRequirement50(resultsByLevel, replayProbe),
        formulas: {
            throughput:
                "completed authentication flows / elapsed timed round wall-clock seconds",
            standardDeviation:
                "sample standard deviation over finite timing values",
            latencyIncreasePercent:
                "(meanAtConcurrencyN - concurrency1Mean) / concurrency1Mean * 100"
        },
        limitations: [
            "The concurrency test uses one registered physical/device identity to create concurrent virtual authentication requests; it does not represent 50 distinct physical devices.",
            "Throughput is observed end-to-end authentication throughput for this local prototype, not theoretical Hyperledger Fabric maximum throughput.",
            "Resource CPU sampling is approximate and only available when --backend-pid is supplied."
        ]
    };
    const report = {
        ...summary,
        observations,
        warmupResults
    };
    const outputFiles = await writeOutputs({
        resultsDir,
        timestamp,
        report,
        summary,
        observations
    });

    summary.outputFiles = outputFiles;
    report.outputFiles = outputFiles;
    await writeJson(outputFiles.summaryPath, summary);
    await writeJson(outputFiles.reportPath, report);

    console.log(JSON.stringify(compactConsoleSummary(summary), null, 2));
}

main().catch((error) => {
    console.error(`Concurrency evaluation failed: ${error.message}`);
    process.exit(1);
});
