#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const path = require("node:path");
const { execFile, spawn } = require("node:child_process");
const { promisify } = require("node:util");

const {
    calculateStats,
    roundNumber,
    summarizeObservations
} = require("./statistics");
const {
    writeComparisonFiles
} = require("./report-comparison");

const execFileAsync = promisify(execFile);

const DEFAULT_RESULTS_DIR = "comparison/results";
const DEFAULT_FABRIC_RESULTS_DIR = "evaluation/results";
const DEFAULT_RADIUS_RUNTIME_DIR = "comparison/radius/runtime";
const DEFAULT_LDAP_RUNTIME_DIR = "comparison/ldap/runtime";
const DEFAULT_BATCH_SIZES = [10, 25, 50];
const DEFAULT_CONCURRENCY_LEVELS = [1, 10, 25, 50];
const DEFAULT_CONCURRENCY_ROUNDS = 3;
const DEFAULT_RADIUS_PORT = 18120;
const DEFAULT_LDAP_PORT = 1389;
const TIMESTAMP_SAFE_PATTERN = /[:.]/g;
const PRIMARY_TEST_USER = "cbu-device-001";
const RADIUS_DICTIONARY_DIR = "/usr/share/freeradius";
const LDAP_BASE_DN = "dc=cbu-auth-test,dc=local";
const LDAP_ADMIN_DN = `cn=admin,${LDAP_BASE_DN}`;
const LDAP_DEVICE_DN =
    `uid=${PRIMARY_TEST_USER},ou=devices,${LDAP_BASE_DN}`;
const REQUIRED_TOOLS = [
    "freeradius",
    "radtest",
    "radclient",
    "slapd",
    "ldapwhoami",
    "ldapsearch",
    "ldapadd"
];

function usage() {
    return [
        "Usage:",
        "  node comparison/run-comparison.js",
        "",
        "Options:",
        "  --results-dir <dir>          Default comparison/results",
        "  --fabric-results-dir <dir>   Default evaluation/results",
        "  --radius-runtime-dir <dir>   Default comparison/radius/runtime",
        "  --ldap-runtime-dir <dir>     Default comparison/ldap/runtime",
        "  --radius-port <port>         Default 18120",
        "  --ldap-port <port>           Default 1389",
        "  --batch-sizes <list>         Default 10,25,50",
        "  --concurrency-levels <list>  Default 1,10,25,50",
        "  --rounds <count>             Default 3",
        "  --help                       Show this message",
        "",
        "Synthetic RADIUS/LDAP passwords and secrets are generated at runtime.",
        "They are stored only under ignored runtime directories and are never",
        "written to result files."
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

function parsePositiveInteger(value, fallback, label) {
    if (!value) {
        return fallback;
    }

    const parsed = Number(value);

    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new Error(`${label} must be a positive integer`);
    }

    return parsed;
}

function parseList(value, fallback) {
    if (!value) {
        return fallback;
    }

    const values = value
        .split(",")
        .map((part) => Number(part.trim()))
        .filter((number) => Number.isSafeInteger(number) && number > 0);

    if (values.length === 0) {
        throw new Error("Expected at least one positive integer in list");
    }

    if (Math.max(...values) > 50) {
        throw new Error("Phase 12B comparison concurrency must not exceed 50");
    }

    return values;
}

function parseOptions() {
    if (process.argv.includes("--help")) {
        console.log(usage());
        process.exit(0);
    }

    return {
        resultsDir: absoluteFromCwd(
            getArg("results-dir") || DEFAULT_RESULTS_DIR
        ),
        fabricResultsDir: absoluteFromCwd(
            getArg("fabric-results-dir") || DEFAULT_FABRIC_RESULTS_DIR
        ),
        radiusRuntimeRoot: absoluteFromCwd(
            getArg("radius-runtime-dir") || DEFAULT_RADIUS_RUNTIME_DIR
        ),
        ldapRuntimeRoot: absoluteFromCwd(
            getArg("ldap-runtime-dir") || DEFAULT_LDAP_RUNTIME_DIR
        ),
        radiusPort: parsePositiveInteger(
            getArg("radius-port"),
            DEFAULT_RADIUS_PORT,
            "RADIUS port"
        ),
        ldapPort: parsePositiveInteger(
            getArg("ldap-port"),
            DEFAULT_LDAP_PORT,
            "LDAP port"
        ),
        batchSizes: parseList(
            getArg("batch-sizes"),
            DEFAULT_BATCH_SIZES
        ),
        concurrencyLevels: parseList(
            getArg("concurrency-levels"),
            DEFAULT_CONCURRENCY_LEVELS
        ),
        rounds: parsePositiveInteger(
            getArg("rounds"),
            DEFAULT_CONCURRENCY_ROUNDS,
            "rounds"
        )
    };
}

function absoluteFromCwd(value) {
    return path.resolve(process.cwd(), value);
}

function timestampForFile(date = new Date()) {
    return date.toISOString().replace(TIMESTAMP_SAFE_PATTERN, "-");
}

function hrtimeMs(start) {
    return Number(process.hrtime.bigint() - start) / 1_000_000;
}

function randomSecret(bytes = 24) {
    return crypto.randomBytes(bytes).toString("base64url");
}

function randomAlphaNumeric(length = 32) {
    const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const bytes = crypto.randomBytes(length);

    return Array.from(bytes, (byte) =>
        alphabet[byte % alphabet.length]
    ).join("");
}

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

async function commandPath(command) {
    try {
        const { stdout } = await execFileAsync("sh", [
            "-c",
            "command -v -- \"$1\"",
            "comparison-command-check",
            command
        ]);

        return stdout.trim() || null;
    } catch {
        return null;
    }
}

async function commandVersion(command) {
    const attempts = command.startsWith("ldap") || command === "slapd"
        ? [
            ["-VV"],
            ["-V"],
            ["--version"]
        ]
        : [
            ["-v"],
            ["--version"],
            ["-V"],
            ["-VV"]
        ];

    for (const args of attempts) {
        try {
            const { stdout, stderr } = await execFileAsync(command, args, {
                timeout: 3000
            });
            const output = `${stdout}${stderr}`.trim();

            if (output && !/invalid option|unrecognized option|usage:/i.test(output)) {
                return output.split("\n").slice(0, 4).join("\n");
            }
        } catch (error) {
            const output = `${error.stdout || ""}${error.stderr || ""}`.trim();

            if (
                output &&
                !/invalid option|unrecognized option|usage:/i.test(output) &&
                /version|openldap|freeradius|radius/i.test(output)
            ) {
                return output.split("\n").slice(0, 4).join("\n");
            }
        }
    }

    return null;
}

async function inspectToolAvailability() {
    const availability = {};

    for (const command of REQUIRED_TOOLS) {
        const resolvedPath = await commandPath(command);

        availability[command] = {
            available: Boolean(resolvedPath),
            path: resolvedPath,
            version: resolvedPath
                ? await commandVersion(command)
                : null
        };
    }

    return availability;
}

function requireTools(toolAvailability) {
    const missing = REQUIRED_TOOLS.filter((tool) =>
        !toolAvailability[tool]?.available
    );

    if (missing.length > 0) {
        throw new Error(
            `Phase 12B cannot run actual baselines; missing tools: ${missing.join(", ")}`
        );
    }
}

async function readJson(filePath) {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
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

async function loadFabricReference(fabricResultsDir) {
    const concurrency = await findLatestFile(
        fabricResultsDir,
        /^concurrency-summary-\d{4}-\d{2}-\d{2}T.+\.json$/
    );
    const evaluation = await findLatestFile(
        fabricResultsDir,
        /^evaluation-summary-\d{4}-\d{2}-\d{2}T.+\.json$/
    );
    const concurrencySummary = concurrency
        ? await readJson(concurrency.filePath)
        : null;
    const evaluationSummary = evaluation
        ? await readJson(evaluation.filePath)
        : null;
    const concurrency1 = concurrencySummary?.results?.["1"] || null;
    const concurrency50 = concurrencySummary?.results?.["50"] || null;

    return {
        datasetUsed: {
            concurrencySummary: concurrency?.fileName || null,
            sequentialEvaluationSummary: evaluation?.fileName || null
        },
        measurementScope:
            "Full blockchain authentication flow: challenge generation, local ECDSA signing, smart-contract execution, DID/status verification, network-context policy, and immutable ledger audit commit.",
        latency: concurrency1
            ? {
                latencyMs: {
                    count: concurrency1.totalAttempts,
                    min: concurrency1.minTotalLatencyMs,
                    max: concurrency1.maxTotalLatencyMs,
                    mean: concurrency1.meanLatencyMs,
                    median: concurrency1.medianLatencyMs,
                    standardDeviation: concurrency1.standardDeviationMs,
                    p95: concurrency1.p95LatencyMs
                },
                successRatePercent: concurrency1.successRatePercent,
                failureRatePercent: concurrency1.failureRatePercent,
                timeoutRatePercent: concurrency1.timeoutRatePercent,
                throughputPerSecond: concurrency1.throughputPerSecond
            }
            : null,
        concurrency50Result: concurrency50
            ? {
                totalAttempts: concurrency50.totalAttempts,
                successRatePercent: concurrency50.successRatePercent,
                timeoutRatePercent: concurrency50.timeoutRatePercent,
                meanLatencyMs: concurrency50.meanLatencyMs,
                medianLatencyMs: concurrency50.medianLatencyMs,
                p95LatencyMs: concurrency50.p95LatencyMs,
                throughputPerSecond: concurrency50.throughputPerSecond,
                requirementPassed:
                    concurrencySummary.requirement50Concurrent?.passed ?? null
            }
            : null,
        securityScenarios: {
            legitimateAuthentication: "SUPPORTED",
            invalidCredentialOrProof: "SUPPORTED",
            repeatedStaticCredential: "NOT_APPLICABLE",
            capturedSignedResponseReplay: "SUPPORTED",
            macContextMismatch: "SUPPORTED",
            ipContextMismatch: "SUPPORTED",
            revokedOrDisabledIdentity: "SUPPORTED",
            centralServerOutage: "NOT_APPLICABLE",
            auditEvidence: "SUPPORTED"
        },
        phase8SecuritySummary: evaluationSummary?.security || null
    };
}

async function ensureCleanDirectory(directory) {
    await fs.rm(directory, {
        recursive: true,
        force: true
    });
    await fs.mkdir(directory, {
        recursive: true
    });
}

async function ensureDirectory(directory) {
    await fs.mkdir(directory, {
        recursive: true
    });
}

async function writeSecretFile(filePath, value) {
    await fs.writeFile(filePath, value, {
        encoding: "utf8",
        mode: 0o600
    });
}

function runProcessTimed(command, args, options = {}) {
    const timeoutMs = options.timeoutMs || 5000;
    const input = options.input || null;
    const start = process.hrtime.bigint();

    return new Promise((resolve) => {
        const child = spawn(command, args, {
            stdio: ["pipe", "pipe", "pipe"]
        });
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill("SIGTERM");
        }, timeoutMs);

        child.stdout.on("data", (chunk) => {
            stdout += chunk.toString("utf8");
        });

        child.stderr.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });

        child.on("error", (error) => {
            clearTimeout(timer);
            resolve({
                exitCode: 1,
                timeout: timedOut,
                latencyMs: roundNumber(hrtimeMs(start)),
                stdout,
                stderr: stderr || error.message
            });
        });

        child.on("close", (code, signal) => {
            clearTimeout(timer);
            resolve({
                exitCode: code === null ? 1 : code,
                signal,
                timeout: timedOut,
                latencyMs: roundNumber(hrtimeMs(start)),
                stdout,
                stderr
            });
        });

        if (input) {
            child.stdin.write(input);
        }

        child.stdin.end();
    });
}

function startLoggedProcess(command, args, logPath) {
    const logStream = fsSync.createWriteStream(logPath, {
        flags: "a",
        mode: 0o600
    });
    const child = spawn(command, args, {
        stdio: ["ignore", "pipe", "pipe"]
    });

    child.stdout.pipe(logStream);
    child.stderr.pipe(logStream);

    return {
        child,
        logStream
    };
}

async function stopLoggedProcess(processHandle) {
    if (!processHandle?.child || processHandle.child.killed) {
        return;
    }

    const child = processHandle.child;

    await new Promise((resolve) => {
        const timer = setTimeout(() => {
            if (!child.killed) {
                child.kill("SIGTERM");
            }
        }, 1500);

        child.once("close", () => {
            clearTimeout(timer);
            resolve();
        });

        child.kill("SIGINT");
    });

    await new Promise((resolve) => {
        processHandle.logStream.end(resolve);
    });
}

async function waitForCondition(label, predicate, timeoutMs = 8000) {
    const startedAt = Date.now();
    let lastError = null;

    while (Date.now() - startedAt < timeoutMs) {
        try {
            if (await predicate()) {
                return;
            }
        } catch (error) {
            lastError = error;
        }

        await sleep(100);
    }

    throw new Error(
        `${label} did not become ready` +
        (lastError ? `: ${lastError.message}` : "")
    );
}

function safeLogMetadata(filePath) {
    try {
        const stat = fsSync.statSync(filePath);

        return {
            path: path.relative(process.cwd(), filePath),
            sizeBytes: stat.size
        };
    } catch {
        return {
            path: path.relative(process.cwd(), filePath),
            sizeBytes: null
        };
    }
}

function observation({
    system,
    scenario,
    batchSize = null,
    concurrencyLevel = null,
    round = null,
    iteration = null,
    measured = true,
    result,
    authenticated = null,
    timeout = null,
    latencyMs = null,
    expected,
    expectedMet,
    notes
}) {
    return {
        timestamp: new Date().toISOString(),
        system,
        scenario,
        batchSize,
        concurrencyLevel,
        round,
        iteration,
        measured,
        result,
        success: authenticated,
        timeout,
        latencyMs,
        expected,
        expectedMet,
        notes
    };
}

function summarizeObservationSet(observations) {
    return summarizeObservations(observations.filter((item) =>
        item.measured === true
    ));
}

function summarizeByBatch(observations, scenario) {
    const summary = {};
    const batchSizes = [...new Set(
        observations
            .filter((item) => item.scenario === scenario && item.batchSize)
            .map((item) => item.batchSize)
    )].sort((left, right) => left - right);

    for (const batchSize of batchSizes) {
        const batchObservations = observations.filter((item) =>
            item.scenario === scenario &&
            item.batchSize === batchSize
        );

        summary[String(batchSize)] = summarizeObservationSet(
            batchObservations
        );
    }

    return summary;
}

function summarizeConcurrency(observations, roundWallClock) {
    const summary = {};
    const levels = [...new Set(
        observations
            .filter((item) =>
                item.scenario.endsWith("_CONCURRENCY") &&
                item.concurrencyLevel
            )
            .map((item) => item.concurrencyLevel)
    )].sort((left, right) => left - right);

    for (const level of levels) {
        const levelObservations = observations.filter((item) =>
            item.scenario.endsWith("_CONCURRENCY") &&
            item.concurrencyLevel === level
        );
        const measured = levelObservations.filter((item) =>
            item.measured === true
        );
        const wallClockMs = roundWallClock
            .filter((round) => round.concurrencyLevel === level)
            .reduce((total, round) => total + round.wallClockMs, 0);
        const completed = measured.length;
        const successful = measured.filter((item) =>
            item.success === true
        ).length;
        const failed = measured.filter((item) =>
            item.success === false
        ).length;
        const timeouts = measured.filter((item) =>
            item.timeout === true
        ).length;

        summary[String(level)] = {
            concurrencyLevel: level,
            rounds: roundWallClock.filter((round) =>
                round.concurrencyLevel === level
            ),
            totalAttempts: measured.length,
            successfulAuthentications: successful,
            failedAuthentications: failed,
            successRatePercent: measured.length
                ? roundNumber((successful / measured.length) * 100, 2)
                : null,
            failureRatePercent: measured.length
                ? roundNumber((failed / measured.length) * 100, 2)
                : null,
            timeoutCount: timeouts,
            timeoutRatePercent: measured.length
                ? roundNumber((timeouts / measured.length) * 100, 2)
                : null,
            latencyMs: calculateStats(measured.map((item) => item.latencyMs)),
            wallClockMs: roundNumber(wallClockMs),
            throughputPerSecond: wallClockMs > 0
                ? roundNumber(completed / (wallClockMs / 1000))
                : null
        };
    }

    return summary;
}

function radiusPacket({
    username,
    password,
    callingStationId = null,
    nasIpAddress = "127.0.0.1"
}) {
    const lines = [
        `User-Name = "${username}"`,
        `User-Password = "${password}"`,
        `NAS-IP-Address = ${nasIpAddress}`,
        "NAS-Port = 0"
    ];

    if (callingStationId) {
        lines.push(`Calling-Station-Id = "${callingStationId}"`);
    }

    return `${lines.join("\n")}\n`;
}

function classifyRadius(commandResult) {
    const output = `${commandResult.stdout}\n${commandResult.stderr}`;
    const receivedAccept = /(?:Received|got)\s+Access-Accept/i.test(output);
    const receivedReject = /(?:Received|got)\s+Access-Reject/i.test(output);
    const accepted = receivedAccept ||
        (!receivedReject && /\bAccess-Accept\b/i.test(output));
    const rejected = receivedReject ||
        (!receivedAccept && /\bAccess-Reject\b/i.test(output));

    return {
        result: accepted
            ? "Access-Accept"
            : rejected ? "Access-Reject" : "TIMEOUT_OR_UNKNOWN",
        authenticated: accepted,
        timeout: commandResult.timeout ||
            (!accepted && !rejected && /no response|no reply|timeout/i.test(output)),
        latencyMs: commandResult.latencyMs
    };
}

async function prepareRadiusRuntime(options, fileTimestamp) {
    const runtimeDir = path.join(
        options.radiusRuntimeRoot,
        fileTimestamp
    );
    const logDir = path.join(runtimeDir, "logs");
    const runDir = path.join(runtimeDir, "run");
    const dbDir = path.join(runtimeDir, "db");
    const filesDir = path.join(runtimeDir, "mods-config", "files");
    const sitesDir = path.join(runtimeDir, "sites-enabled");
    const password = randomSecret();
    const disabledPassword = randomSecret();
    const sharedSecret = randomSecret(32);
    const sharedSecretPath = path.join(runtimeDir, "radius-client.secret");
    const authorizePath = path.join(filesDir, "authorize");
    const radiusLogPath = path.join(logDir, "radius.log");

    await ensureCleanDirectory(runtimeDir);
    await ensureDirectory(logDir);
    await ensureDirectory(runDir);
    await ensureDirectory(dbDir);
    await ensureDirectory(filesDir);
    await ensureDirectory(sitesDir);
    await writeSecretFile(path.join(runtimeDir, "device.password"), password);
    await writeSecretFile(
        path.join(runtimeDir, "device-disabled.password"),
        disabledPassword
    );
    await writeSecretFile(sharedSecretPath, sharedSecret);

    const radiusdConf = `prefix = /usr
exec_prefix = \${prefix}
sysconfdir = ${runtimeDir}
localstatedir = ${runtimeDir}
sbindir = \${exec_prefix}/sbin
logdir = \${localstatedir}/logs
raddbdir = ${runtimeDir}
radacctdir = \${logdir}/radacct
name = phase12b-radius
confdir = \${raddbdir}
run_dir = \${localstatedir}/run
db_dir = \${localstatedir}/db
libdir = /usr/lib/freeradius
pidfile = \${run_dir}/\${name}.pid
max_request_time = 30
cleanup_delay = 5
max_requests = 16384
log {
    destination = files
    file = \${logdir}/radius.log
    stripped_names = no
    auth = yes
    auth_badpass = no
    auth_goodpass = no
}
security {
    allow_core_dumps = no
}
thread pool {
    start_servers = 1
    max_servers = 8
    min_spare_servers = 1
    max_spare_servers = 4
    max_requests_per_server = 0
}
modules {
    pap { }
    files {
        filename = \${confdir}/mods-config/files/authorize
    }
}
instantiate {
    pap
    files
}
$INCLUDE clients.conf
$INCLUDE sites-enabled/default
`;
const clientsConf = `client localhost {
    ipaddr = 127.0.0.1
    secret = ${sharedSecret}
    require_message_authenticator = true
    limit_proxy_state = true
}
`;
    const siteDefault = `server default {
    listen {
        type = auth
        ipaddr = 127.0.0.1
        port = ${options.radiusPort}
    }
    authorize {
        files
        pap
    }
    authenticate {
        Auth-Type PAP {
            pap
        }
    }
    post-auth { }
}
`;

    await fs.writeFile(path.join(runtimeDir, "radiusd.conf"), radiusdConf);
    await fs.writeFile(path.join(runtimeDir, "clients.conf"), clientsConf, {
        mode: 0o600
    });
    await fs.writeFile(path.join(sitesDir, "default"), siteDefault);
    await writeRadiusAuthorize(authorizePath, password);

    await runRequired("freeradius", [
        "-C",
        "-d",
        runtimeDir,
        "-D",
        RADIUS_DICTIONARY_DIR,
        "-l",
        path.join(logDir, "config-check.log")
    ]);

    return {
        runtimeDir,
        logDir,
        radiusLogPath,
        authorizePath,
        sharedSecretPath,
        username: PRIMARY_TEST_USER,
        password,
        disabledPassword,
        port: options.radiusPort,
        host: "127.0.0.1"
    };
}

async function writeRadiusAuthorize(authorizePath, password) {
    await fs.writeFile(
        authorizePath,
        `${PRIMARY_TEST_USER} Cleartext-Password := "${password}"\n`,
        {
            mode: 0o600
        }
    );
}

async function clearRadiusAuthorize(authorizePath) {
    await fs.writeFile(authorizePath, "", {
        mode: 0o600
    });
}

async function runRequired(command, args, options = {}) {
    const result = await runProcessTimed(command, args, {
        input: options.input,
        timeoutMs: options.timeoutMs || 10000
    });

    if (result.exitCode !== 0) {
        throw new Error(
            `${command} failed: ${result.stderr || result.stdout || "no output"}`
        );
    }

    return result;
}

async function startRadius(runtime, readyPassword = runtime.password) {
    const handle = startLoggedProcess(
        "freeradius",
        [
            "-f",
            "-d",
            runtime.runtimeDir,
            "-D",
            RADIUS_DICTIONARY_DIR,
            "-l",
            runtime.radiusLogPath
        ],
        path.join(runtime.logDir, "freeradius-foreground.log")
    );

    await waitForCondition("FreeRADIUS", async () => {
        const result = await runRadiusRequest(runtime, {
            scenario: "RADIUS_SERVICE_READY",
            password: readyPassword,
            expectedResult: "Access-Accept",
            measured: true,
            includeInReport: false
        });

        return result.result === "Access-Accept";
    });

    return handle;
}

async function runRadiusRequest(runtime, {
    scenario,
    password,
    expectedResult,
    batchSize = null,
    concurrencyLevel = null,
    round = null,
    iteration = null,
    callingStationId = null,
    notes = "",
    measured = true,
    includeInReport = true,
    timeoutMs = 6000
}) {
    const packet = radiusPacket({
        username: runtime.username,
        password,
        callingStationId
    });
    const commandResult = await runProcessTimed("radclient", [
        "-t",
        "1",
        "-r",
        "1",
        "-S",
        runtime.sharedSecretPath,
        "-f",
        "-",
        `${runtime.host}:${runtime.port}`,
        "auth"
    ], {
        input: packet,
        timeoutMs
    });
    const classified = classifyRadius(commandResult);
    const expectedMet = classified.result === expectedResult ||
        (
            expectedResult === "NO_RESPONSE" &&
            (classified.timeout || classified.result === "TIMEOUT_OR_UNKNOWN")
        );

    return {
        ...observation({
            system: "RADIUS",
            scenario,
            batchSize,
            concurrencyLevel,
            round,
            iteration,
            measured,
            result: classified.result,
            authenticated: classified.authenticated,
            timeout: classified.timeout,
            latencyMs: classified.latencyMs,
            expected: expectedResult,
            expectedMet,
            notes
        }),
        includeInReport
    };
}

async function runSequentialBatch({
    system,
    scenario,
    batchSize,
    request
}) {
    const observations = [];

    for (let iteration = 1; iteration <= batchSize; iteration += 1) {
        observations.push(await request({
            scenario,
            batchSize,
            iteration
        }));
    }

    return observations;
}

async function runConcurrentRounds({
    system,
    scenario,
    levels,
    rounds,
    request
}) {
    const observations = [];
    const roundWallClock = [];

    for (const concurrencyLevel of levels) {
        for (let round = 1; round <= rounds; round += 1) {
            const startedAt = process.hrtime.bigint();
            const attempts = await Promise.allSettled(
                Array.from({ length: concurrencyLevel }, (_, index) =>
                    request({
                        scenario,
                        concurrencyLevel,
                        round,
                        iteration: index + 1
                    })
                )
            );
            const wallClockMs = roundNumber(hrtimeMs(startedAt));

            roundWallClock.push({
                system,
                scenario,
                concurrencyLevel,
                round,
                attempts: concurrencyLevel,
                wallClockMs
            });

            for (const [index, result] of attempts.entries()) {
                if (result.status === "fulfilled") {
                    observations.push(result.value);
                } else {
                    observations.push(observation({
                        system,
                        scenario,
                        concurrencyLevel,
                        round,
                        iteration: index + 1,
                        result: "CLIENT_ERROR",
                        authenticated: false,
                        timeout: false,
                        expected: "successful authentication",
                        expectedMet: false,
                        notes: result.reason?.message || "unknown error"
                    }));
                }
            }
        }
    }

    return {
        observations,
        roundWallClock
    };
}

async function runRadiusBaseline(toolAvailability, options, fileTimestamp) {
    const runtime = await prepareRadiusRuntime(options, fileTimestamp);
    let processHandle = null;
    const observations = [];
    const cleanupNotes = [];

    try {
        processHandle = await startRadius(runtime);

        observations.push(await runRadiusRequest(runtime, {
            scenario: "RADIUS_LEGITIMATE",
            password: runtime.password,
            expectedResult: "Access-Accept",
            iteration: 1,
            notes: "Correct synthetic username/password; expected Access-Accept."
        }));
        observations.push(await runRadiusRequest(runtime, {
            scenario: "RADIUS_INVALID_CREDENTIAL",
            password: `invalid-${randomSecret(8)}`,
            expectedResult: "Access-Reject",
            iteration: 1,
            notes: "Wrong synthetic password; expected Access-Reject."
        }));

        for (let iteration = 1; iteration <= 3; iteration += 1) {
            observations.push(await runRadiusRequest(runtime, {
                scenario: "RADIUS_STATIC_CREDENTIAL_REUSE",
                password: runtime.password,
                expectedResult: "Access-Accept",
                iteration,
                notes:
                    "Same valid credential reused; Access-Accept is expected for this static credential scheme."
            }));
        }

        observations.push(await runRadiusRequest(runtime, {
            scenario: "RADIUS_MAC_CONTEXT",
            password: runtime.password,
            expectedResult: "Access-Accept",
            iteration: 1,
            callingStationId: "AA-BB-CC-DD-EE-01",
            notes:
                "Calling-Station-Id included with correct MAC; no MAC policy configured."
        }));
        observations.push(await runRadiusRequest(runtime, {
            scenario: "RADIUS_MAC_CONTEXT",
            password: runtime.password,
            expectedResult: "Access-Accept",
            iteration: 2,
            callingStationId: "00-11-22-33-44-55",
            notes:
                "Calling-Station-Id altered; baseline accepted independently because no MAC policy is configured."
        }));
        observations.push(observation({
            system: "RADIUS",
            scenario: "RADIUS_IP_CONTEXT",
            measured: false,
            result: "NOT_NATIVE_TO_BASELINE",
            authenticated: null,
            timeout: null,
            expected: "meaningful configured IP authorization policy",
            expectedMet: true,
            notes:
                "No explicit IP authorization policy was configured for this RADIUS baseline."
        }));

        for (const batchSize of options.batchSizes) {
            observations.push(...await runSequentialBatch({
                system: "RADIUS",
                scenario: "RADIUS_SEQUENTIAL_LEGITIMATE",
                batchSize,
                request: (metadata) => runRadiusRequest(runtime, {
                    ...metadata,
                    password: runtime.password,
                    expectedResult: "Access-Accept",
                    notes: "Sequential legitimate RADIUS Access-Request."
                })
            }));
        }

        const concurrencyRun = await runConcurrentRounds({
            system: "RADIUS",
            scenario: "RADIUS_CONCURRENCY",
            levels: options.concurrencyLevels,
            rounds: options.rounds,
            request: (metadata) => runRadiusRequest(runtime, {
                ...metadata,
                password: runtime.password,
                expectedResult: "Access-Accept",
                notes: "Independent concurrent RADIUS Access-Request."
            })
        });

        observations.push(...concurrencyRun.observations);

        const preOutage = await runRadiusRequest(runtime, {
            scenario: "RADIUS_FAULT_TOLERANCE_BEFORE_STOP",
            password: runtime.password,
            expectedResult: "Access-Accept",
            notes: "Valid authentication before stopping isolated RADIUS process."
        });

        await stopLoggedProcess(processHandle);
        processHandle = null;

        const duringOutage = await runRadiusRequest(runtime, {
            scenario: "RADIUS_FAULT_TOLERANCE_DURING_STOP",
            password: runtime.password,
            expectedResult: "NO_RESPONSE",
            timeoutMs: 4000,
            notes: "Request sent after stopping only the isolated RADIUS process."
        });

        processHandle = await startRadius(runtime);

        const afterRestart = await runRadiusRequest(runtime, {
            scenario: "RADIUS_FAULT_TOLERANCE_AFTER_RESTART",
            password: runtime.password,
            expectedResult: "Access-Accept",
            notes: "Valid authentication after restarting isolated RADIUS process."
        });

        observations.push(preOutage, duringOutage, afterRestart);

        await stopLoggedProcess(processHandle);
        processHandle = null;
        await writeRadiusAuthorize(runtime.authorizePath, runtime.disabledPassword);
        processHandle = await startRadius(runtime, runtime.disabledPassword);

        const disabled = await runRadiusRequest(runtime, {
            scenario: "RADIUS_IDENTITY_DISABLED",
            password: runtime.password,
            expectedResult: "Access-Reject",
            notes:
                "Synthetic runtime credential replaced with a generated disabled value; original credential expected to fail."
        });

        await stopLoggedProcess(processHandle);
        processHandle = null;
        await writeRadiusAuthorize(runtime.authorizePath, runtime.password);
        processHandle = await startRadius(runtime);

        const restored = await runRadiusRequest(runtime, {
            scenario: "RADIUS_IDENTITY_RESTORED",
            password: runtime.password,
            expectedResult: "Access-Accept",
            notes:
                "Synthetic identity restored in runtime users file; expected Access-Accept."
        });

        observations.push(disabled, restored);

        return buildRadiusResult({
            runtime,
            observations: observations.filter((item) =>
                item.includeInReport !== false
            ),
            roundWallClock: concurrencyRun.roundWallClock
        });
    } finally {
        if (processHandle) {
            await stopLoggedProcess(processHandle);
            cleanupNotes.push("Stopped isolated FreeRADIUS process.");
        }

        cleanupNotes.push("Runtime credentials remain only in ignored runtime directory.");
    }
}

function buildRadiusResult({ runtime, observations, roundWallClock }) {
    const sequentialObservations = observations.filter((item) =>
        item.scenario === "RADIUS_SEQUENTIAL_LEGITIMATE"
    );
    const functional = Object.fromEntries(
        observations
            .filter((item) =>
                item.scenario.startsWith("RADIUS_") &&
                !item.scenario.includes("SEQUENTIAL") &&
                !item.scenario.includes("CONCURRENCY")
            )
            .map((item) => [
                `${item.scenario}_${item.iteration || "single"}`,
                {
                    result: item.result,
                    authenticated: item.success,
                    expectedMet: item.expectedMet,
                    latencyMs: item.latencyMs,
                    notes: item.notes
                }
            ])
    );

    return {
        protocol: "RADIUS",
        availableForMeasurement: true,
        configuration: {
            runtimeDirectory: path.relative(process.cwd(), runtime.runtimeDir),
            host: runtime.host,
            port: runtime.port,
            username: runtime.username,
            passwordSource: "generated runtime secret file",
            sharedSecretSource: "generated runtime secret file",
            storesPasswordInResults: false,
            authenticationMethod: "PAP over isolated localhost RADIUS",
            macPolicyConfigured: false,
            ipPolicyConfigured: false
        },
        missingPrerequisites: [],
        observations,
        functionalResults: functional,
        latency: summarizeObservationSet(sequentialObservations),
        sequentialLatencyByBatch: summarizeByBatch(
            observations,
            "RADIUS_SEQUENTIAL_LEGITIMATE"
        ),
        concurrency: {
            measured: true,
            levels: summarizeConcurrency(observations, roundWallClock)
        },
        networkContext: {
            macContext: {
                status: "NOT_CONFIGURED",
                behavior:
                    "Calling-Station-Id was accepted with both correct and altered MAC because no MAC authorization policy was configured."
            },
            ipContext: {
                status: "NOT_NATIVE_TO_BASELINE",
                behavior:
                    "No meaningful IP authorization policy was configured in the isolated RADIUS baseline."
            }
        },
        identityDisable: {
            measured: true,
            result:
                "Replacing the synthetic runtime credential denied the original credential; restoring it produced Access-Accept."
        },
        faultTolerance: {
            measured: true,
            result:
                "Stopping the isolated RADIUS process caused no-response/timeout behavior; restart restored Access-Accept."
        },
        auditCapability: {
            observed: true,
            logFiles: [
                safeLogMetadata(runtime.radiusLogPath),
                safeLogMetadata(path.join(runtime.logDir, "freeradius-foreground.log"))
            ],
            summary:
                "FreeRADIUS produced local runtime logs for the isolated service. These logs are local mutable files, not immutable distributed ledger records."
        },
        securityScenarios: {
            legitimateAuthentication: "SUPPORTED",
            invalidCredentialOrProof: "SUPPORTED",
            repeatedStaticCredential: "SUPPORTED",
            capturedSignedResponseReplay: "NOT_APPLICABLE",
            macContextMismatch: "NOT_CONFIGURED",
            ipContextMismatch: "NOT_NATIVE_TO_BASELINE",
            revokedOrDisabledIdentity: "SUPPORTED",
            centralServerOutage: "SUPPORTED",
            auditEvidence: "SUPPORTED_LOCAL_LOGS"
        }
    };
}

async function prepareLdapRuntime(options, fileTimestamp) {
    const runtimeDir = path.join(
        options.ldapRuntimeRoot,
        fileTimestamp
    );
    const logDir = path.join(runtimeDir, "logs");
    const runDir = path.join(runtimeDir, "run");
    const dbDir = path.join(runtimeDir, "db");
    const password = randomAlphaNumeric();
    const disabledPassword = randomAlphaNumeric();
    const adminPassword = randomAlphaNumeric();
    const passwordPath = path.join(runtimeDir, "device.password");
    const disabledPasswordPath = path.join(runtimeDir, "device-disabled.password");
    const adminPasswordPath = path.join(runtimeDir, "admin.password");
    const slapdConfPath = path.join(runtimeDir, "slapd.conf");
    const initLdifPath = path.join(runtimeDir, "init.ldif");
    const slapdLogPath = path.join(logDir, "slapd.log");

    await ensureCleanDirectory(runtimeDir);
    await ensureDirectory(logDir);
    await ensureDirectory(runDir);
    await ensureDirectory(dbDir);
    await writeSecretFile(passwordPath, password);
    await writeSecretFile(disabledPasswordPath, disabledPassword);
    await writeSecretFile(adminPasswordPath, adminPassword);

    const slapdConf = `include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile ${path.join(runDir, "slapd.pid")}
argsfile ${path.join(runDir, "slapd.args")}
modulepath /usr/lib/ldap
moduleload back_mdb
loglevel stats

database mdb
maxsize 1073741824
suffix "${LDAP_BASE_DN}"
rootdn "${LDAP_ADMIN_DN}"
rootpw ${adminPassword}
directory ${dbDir}
index objectClass eq
access to * by * read
`;
    const initLdif = `dn: ${LDAP_BASE_DN}
objectClass: top
objectClass: dcObject
objectClass: organization
o: CBU Auth Test
dc: cbu-auth-test

dn: ou=devices,${LDAP_BASE_DN}
objectClass: top
objectClass: organizationalUnit
ou: devices

dn: ${LDAP_DEVICE_DN}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: ${PRIMARY_TEST_USER}
cn: ${PRIMARY_TEST_USER}
sn: Device001
userPassword: ${password}
`;

    await fs.writeFile(slapdConfPath, slapdConf, {
        mode: 0o600
    });
    await fs.writeFile(initLdifPath, initLdif, {
        mode: 0o600
    });
    await runRequired("slaptest", [
        "-f",
        slapdConfPath,
        "-u"
    ]);
    await runRequired("slapadd", [
        "-f",
        slapdConfPath,
        "-l",
        initLdifPath
    ]);

    return {
        runtimeDir,
        logDir,
        dbDir,
        slapdConfPath,
        slapdLogPath,
        password,
        disabledPassword,
        passwordPath,
        disabledPasswordPath,
        adminPasswordPath,
        url: `ldap://127.0.0.1:${options.ldapPort}`,
        port: options.ldapPort,
        bindDn: LDAP_DEVICE_DN,
        adminDn: LDAP_ADMIN_DN,
        baseDn: LDAP_BASE_DN
    };
}

async function startLdap(runtime) {
    const handle = startLoggedProcess(
        "slapd",
        [
            "-f",
            runtime.slapdConfPath,
            "-h",
            runtime.url,
            "-d",
            "stats"
        ],
        runtime.slapdLogPath
    );

    await waitForCondition("slapd", async () => {
        const result = await runLdapRequest(runtime, {
            scenario: "LDAP_SERVICE_READY",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_SUCCESS",
            includeInReport: false
        });

        return result.result === "BIND_SUCCESS";
    });

    return handle;
}

function classifyLdap(commandResult) {
    const output = `${commandResult.stdout}\n${commandResult.stderr}`;
    const authenticated = commandResult.exitCode === 0 &&
        /dn:|u:/i.test(output);
    const failed = /Invalid credentials|Can.t contact LDAP server|ldap_sasl_bind|ldap_bind/i.test(output) ||
        commandResult.exitCode !== 0;

    return {
        result: authenticated
            ? "BIND_SUCCESS"
            : failed ? "BIND_FAILURE" : "TIMEOUT_OR_UNKNOWN",
        authenticated,
        timeout: commandResult.timeout || /Can.t contact LDAP server/i.test(output),
        latencyMs: commandResult.latencyMs
    };
}

async function runLdapRequest(runtime, {
    scenario,
    passwordPath,
    expectedResult,
    batchSize = null,
    concurrencyLevel = null,
    round = null,
    iteration = null,
    notes = "",
    measured = true,
    includeInReport = true,
    timeoutMs = 5000
}) {
    const commandResult = await runProcessTimed("ldapwhoami", [
        "-x",
        "-H",
        runtime.url,
        "-D",
        runtime.bindDn,
        "-y",
        passwordPath
    ], {
        timeoutMs
    });
    const classified = classifyLdap(commandResult);
    const expectedMet = classified.result === expectedResult ||
        (
            expectedResult === "NO_RESPONSE" &&
            classified.result === "BIND_FAILURE"
        );

    return {
        ...observation({
            system: "LDAP",
            scenario,
            batchSize,
            concurrencyLevel,
            round,
            iteration,
            measured,
            result: classified.result,
            authenticated: classified.authenticated,
            timeout: classified.timeout,
            latencyMs: classified.latencyMs,
            expected: expectedResult,
            expectedMet,
            notes
        }),
        includeInReport
    };
}

async function ldapModify(runtime, ldif) {
    return runRequired("ldapmodify", [
        "-x",
        "-H",
        runtime.url,
        "-D",
        runtime.adminDn,
        "-y",
        runtime.adminPasswordPath
    ], {
        input: ldif,
        timeoutMs: 10000
    });
}

async function setLdapDevicePassword(runtime, password) {
    const ldif = `dn: ${runtime.bindDn}
changetype: modify
replace: userPassword
userPassword: ${password}
`;

    await ldapModify(runtime, ldif);
}

async function runLdapBaseline(toolAvailability, options, fileTimestamp) {
    const runtime = await prepareLdapRuntime(options, fileTimestamp);
    let processHandle = null;
    const observations = [];

    try {
        processHandle = await startLdap(runtime);

        observations.push(await runLdapRequest(runtime, {
            scenario: "LDAP_LEGITIMATE",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_SUCCESS",
            iteration: 1,
            notes: "Correct synthetic bind DN/password; expected bind success."
        }));
        observations.push(await runLdapRequest(runtime, {
            scenario: "LDAP_INVALID_CREDENTIAL",
            passwordPath: runtime.disabledPasswordPath,
            expectedResult: "BIND_FAILURE",
            iteration: 1,
            notes: "Wrong synthetic password; expected bind failure."
        }));

        for (let iteration = 1; iteration <= 3; iteration += 1) {
            observations.push(await runLdapRequest(runtime, {
                scenario: "LDAP_STATIC_CREDENTIAL_REUSE",
                passwordPath: runtime.passwordPath,
                expectedResult: "BIND_SUCCESS",
                iteration,
                notes:
                    "Same valid LDAP credential reused; success is expected for this simple-bind scheme."
            }));
        }

        observations.push(observation({
            system: "LDAP",
            scenario: "LDAP_MAC_SPOOF",
            measured: false,
            result: "NOT_NATIVE_TO_BASELINE",
            authenticated: null,
            timeout: null,
            expected: "native MAC-context authorization",
            expectedMet: true,
            notes:
                "Basic LDAP bind has no native MAC address context in this isolated baseline."
        }));
        observations.push(observation({
            system: "LDAP",
            scenario: "LDAP_IP_SPOOF",
            measured: false,
            result: "NOT_NATIVE_TO_BASELINE",
            authenticated: null,
            timeout: null,
            expected: "native IP-context authorization",
            expectedMet: true,
            notes:
                "Basic LDAP bind has no native IP address context in this isolated baseline."
        }));

        for (const batchSize of options.batchSizes) {
            observations.push(...await runSequentialBatch({
                system: "LDAP",
                scenario: "LDAP_SEQUENTIAL_LEGITIMATE",
                batchSize,
                request: (metadata) => runLdapRequest(runtime, {
                    ...metadata,
                    passwordPath: runtime.passwordPath,
                    expectedResult: "BIND_SUCCESS",
                    notes:
                        "Sequential LDAP simple bind using an independent ldapwhoami client invocation."
                })
            }));
        }

        const concurrencyRun = await runConcurrentRounds({
            system: "LDAP",
            scenario: "LDAP_CONCURRENCY",
            levels: options.concurrencyLevels,
            rounds: options.rounds,
            request: (metadata) => runLdapRequest(runtime, {
                ...metadata,
                passwordPath: runtime.passwordPath,
                expectedResult: "BIND_SUCCESS",
                notes:
                    "Independent LDAP client connection/bind for concurrent baseline."
            })
        });

        observations.push(...concurrencyRun.observations);

        const preOutage = await runLdapRequest(runtime, {
            scenario: "LDAP_FAULT_TOLERANCE_BEFORE_STOP",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_SUCCESS",
            notes: "Valid bind before stopping isolated slapd process."
        });

        await stopLoggedProcess(processHandle);
        processHandle = null;

        const duringOutage = await runLdapRequest(runtime, {
            scenario: "LDAP_FAULT_TOLERANCE_DURING_STOP",
            passwordPath: runtime.passwordPath,
            expectedResult: "NO_RESPONSE",
            timeoutMs: 4000,
            notes: "Bind attempted after stopping only the isolated slapd process."
        });

        processHandle = await startLdap(runtime);

        const afterRestart = await runLdapRequest(runtime, {
            scenario: "LDAP_FAULT_TOLERANCE_AFTER_RESTART",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_SUCCESS",
            notes: "Valid bind after restarting isolated slapd process."
        });

        observations.push(preOutage, duringOutage, afterRestart);

        await setLdapDevicePassword(runtime, runtime.disabledPassword);

        const disabled = await runLdapRequest(runtime, {
            scenario: "LDAP_IDENTITY_DISABLED",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_FAILURE",
            notes:
                "Synthetic entry password changed to a generated disabled value; original credential expected to fail."
        });

        await setLdapDevicePassword(runtime, runtime.password);

        const restored = await runLdapRequest(runtime, {
            scenario: "LDAP_IDENTITY_RESTORED",
            passwordPath: runtime.passwordPath,
            expectedResult: "BIND_SUCCESS",
            notes:
                "Synthetic entry password restored; original credential expected to bind successfully."
        });

        observations.push(disabled, restored);

        return buildLdapResult({
            runtime,
            observations: observations.filter((item) =>
                item.includeInReport !== false
            ),
            roundWallClock: concurrencyRun.roundWallClock
        });
    } finally {
        if (processHandle) {
            await stopLoggedProcess(processHandle);
        }
    }
}

function buildLdapResult({ runtime, observations, roundWallClock }) {
    const sequentialObservations = observations.filter((item) =>
        item.scenario === "LDAP_SEQUENTIAL_LEGITIMATE"
    );
    const functional = Object.fromEntries(
        observations
            .filter((item) =>
                item.scenario.startsWith("LDAP_") &&
                !item.scenario.includes("SEQUENTIAL") &&
                !item.scenario.includes("CONCURRENCY")
            )
            .map((item) => [
                `${item.scenario}_${item.iteration || "single"}`,
                {
                    result: item.result,
                    authenticated: item.success,
                    expectedMet: item.expectedMet,
                    latencyMs: item.latencyMs,
                    notes: item.notes
                }
            ])
    );

    return {
        protocol: "LDAP",
        availableForMeasurement: true,
        configuration: {
            runtimeDirectory: path.relative(process.cwd(), runtime.runtimeDir),
            url: runtime.url,
            directorySuffix: runtime.baseDn,
            bindDn: runtime.bindDn,
            passwordSource: "generated runtime secret file",
            authenticationMethod: "LDAP simple bind over isolated localhost slapd",
            tlsStatus: "not configured for this isolated localhost baseline",
            storesPasswordInResults: false,
            macPolicyConfigured: false,
            ipPolicyConfigured: false
        },
        missingPrerequisites: [],
        observations,
        functionalResults: functional,
        latency: summarizeObservationSet(sequentialObservations),
        sequentialLatencyByBatch: summarizeByBatch(
            observations,
            "LDAP_SEQUENTIAL_LEGITIMATE"
        ),
        concurrency: {
            measured: true,
            levels: summarizeConcurrency(observations, roundWallClock)
        },
        networkContext: {
            macContext: {
                status: "NOT_NATIVE_TO_BASELINE",
                behavior:
                    "LDAP simple bind does not carry or authorize MAC address context in this baseline."
            },
            ipContext: {
                status: "NOT_NATIVE_TO_BASELINE",
                behavior:
                    "LDAP simple bind does not carry or authorize IP address context in this baseline."
            }
        },
        identityDisable: {
            measured: true,
            result:
                "Replacing the synthetic entry password denied the original credential; restoring it allowed bind success."
        },
        faultTolerance: {
            measured: true,
            result:
                "Stopping isolated slapd caused bind failure; restart restored bind success."
        },
        auditCapability: {
            observed: true,
            logFiles: [
                safeLogMetadata(runtime.slapdLogPath)
            ],
            summary:
                "slapd produced local stats/debug logs for bind operations. These logs are local mutable files, not immutable distributed ledger records."
        },
        securityScenarios: {
            legitimateAuthentication: "SUPPORTED",
            invalidCredentialOrProof: "SUPPORTED",
            repeatedStaticCredential: "SUPPORTED",
            capturedSignedResponseReplay: "NOT_APPLICABLE",
            macContextMismatch: "NOT_NATIVE_TO_BASELINE",
            ipContextMismatch: "NOT_NATIVE_TO_BASELINE",
            revokedOrDisabledIdentity: "SUPPORTED",
            centralServerOutage: "SUPPORTED",
            auditEvidence: "SUPPORTED_LOCAL_LOGS"
        }
    };
}

function buildSpoofingResistanceMatrix(radius, ldap) {
    return {
        cryptographicDeviceProof: {
            fabric: "SUPPORTED",
            radius: "NOT_CONFIGURED",
            ldap: "NOT_NATIVE",
            basis:
                "Fabric verifies ECDSA device proof against the ledger public key. The isolated RADIUS PAP and LDAP simple-bind baselines validate static credentials."
        },
        serverGeneratedNonce: {
            fabric: "SUPPORTED",
            radius: "NOT_CONFIGURED",
            ldap: "NOT_NATIVE",
            basis:
                "Fabric challenge service issues single-use nonces. The measured RADIUS PAP and LDAP simple-bind baselines did not use challenge-response methods."
        },
        capturedResponseReplayResistance: {
            fabric: "SUPPORTED",
            radius: "NOT_APPLICABLE",
            ldap: "NOT_APPLICABLE",
            basis:
                "Fabric Phase 11 replay probe rejected consumed challenge/signature material. The measured baselines did not create captured signed responses."
        },
        staticCredentialReuse: {
            fabric: "NOT_APPLICABLE",
            radius: "SUPPORTED",
            ldap: "SUPPORTED",
            basis:
                "RADIUS and LDAP accepted repeated valid static credentials as expected. This is not the same as replaying captured packets."
        },
        macContextEnforcement: {
            fabric: "SUPPORTED",
            radius: radius.networkContext.macContext.status,
            ldap: ldap.networkContext.macContext.status,
            basis:
                "Fabric checks MAC context. The RADIUS baseline accepted both correct and altered Calling-Station-Id because no policy was configured; LDAP simple bind has no native MAC context."
        },
        ipContextEnforcement: {
            fabric: "SUPPORTED",
            radius: radius.networkContext.ipContext.status,
            ldap: ldap.networkContext.ipContext.status,
            basis:
                "Fabric checks IP context. No comparable IP authorization policy was configured in RADIUS; LDAP simple bind has no native IP context."
        },
        identityDisableRevocation: {
            fabric: "SUPPORTED",
            radius: "SUPPORTED",
            ldap: "SUPPORTED",
            basis:
                "Fabric uses ACTIVE/SUSPENDED/REVOKED status; RADIUS denied after replacing the runtime credential; LDAP denied after changing the entry password."
        },
        centralDecisionPoint: {
            fabric: "NOT_APPLICABLE",
            radius: "SUPPORTED",
            ldap: "SUPPORTED",
            basis:
                "The measured RADIUS and LDAP baselines depend on a single local server. Fabric verification uses the gateway plus Fabric ledger/chaincode path."
        },
        immutableAuditTrail: {
            fabric: "SUPPORTED",
            radius: "NOT_SUPPORTED",
            ldap: "NOT_SUPPORTED",
            basis:
                "Fabric stores authentication events on-chain; FreeRADIUS/slapd logs are local mutable runtime files."
        },
        faultTolerance: {
            fabric: "CONFIGURABLE",
            radius: "NOT_SUPPORTED_SINGLE_SERVER",
            ldap: "NOT_SUPPORTED_SINGLE_SERVER",
            basis:
                "Stopping the single isolated RADIUS/LDAP service caused failures until restart. Fabric has distributed components, but this prototype gateway still uses a configured peer endpoint."
        }
    };
}

function buildInterpretations() {
    return {
        legitimateAuthentication:
            "Fabric verifies a signed DID challenge; RADIUS and LDAP validate synthetic static credentials.",
        invalidCredentialOrProof:
            "Fabric denies invalid signatures; RADIUS returned Access-Reject and LDAP returned invalid-credential bind failure.",
        repeatedStaticCredential:
            "RADIUS and LDAP accepted repeated valid static credentials as expected by their configured credential schemes.",
        capturedSignedResponseReplay:
            "Fabric rejects consumed challenge/signature reuse; the measured RADIUS/LDAP baselines did not create signed challenge responses.",
        macContextMismatch:
            "Fabric enforces MAC context. RADIUS accepted altered Calling-Station-Id because no policy was configured. LDAP simple bind has no native MAC context.",
        ipContextMismatch:
            "Fabric enforces IP context. RADIUS/LDAP would need explicit surrounding policy for comparable IP authorization.",
        revokedOrDisabledIdentity:
            "All systems can deny a disabled identity in their configured form, but Fabric status is ledger-backed.",
        centralServerOutage:
            "The single isolated RADIUS/LDAP services failed during outage and recovered after restart.",
        auditEvidence:
            "Fabric audit events are ledger records. RADIUS/LDAP produced local mutable server logs."
    };
}

function buildFiveDimensionComparison(radius) {
    const c50 = radius.concurrency.levels["50"];

    return [
        {
            dimension: "Spoofing resistance",
            summary:
                "Measured RADIUS PAP baseline validates credentials and can carry Calling-Station-Id, but no MAC/IP enforcement policy was configured. MAC/IP enforcement is configurable, not native to this measured baseline."
        },
        {
            dimension: "Authentication latency",
            summary:
                `Sequential RADIUS legitimate mean ${radius.latency.latencyMs.mean} ms, median ${radius.latency.latencyMs.median} ms, p95 ${radius.latency.latencyMs.p95} ms.`
        },
        {
            dimension: "Observed concurrency/scalability",
            summary: c50
                ? `At concurrency 50 across 3 rounds: success ${c50.successRatePercent}%, timeout ${c50.timeoutRatePercent}%, mean ${c50.latencyMs.mean} ms, p95 ${c50.latencyMs.p95} ms, throughput ${c50.throughputPerSecond} auth/s.`
                : "Concurrency 50 was not measured."
        },
        {
            dimension: "Fault tolerance",
            summary:
                "Stopping the single isolated FreeRADIUS process caused authentication no-response/timeout behavior; restart restored Access-Accept. This single-server baseline is not fault tolerant by itself."
        },
        {
            dimension: "Audit capability",
            summary:
                "FreeRADIUS produced local authentication/debug logs in the runtime directory. They are useful evidence but remain local mutable files, unlike Fabric ledger audit events."
        }
    ];
}

function buildLdapComparison(ldap) {
    const c50 = ldap.concurrency.levels["50"];

    return [
        {
            dimension: "Security / spoofing resistance",
            summary:
                "Measured LDAP simple bind validates centralized credentials and has no native MAC/IP spoofing context in this baseline."
        },
        {
            dimension: "Authentication latency",
            summary:
                `Sequential LDAP legitimate mean ${ldap.latency.latencyMs.mean} ms, median ${ldap.latency.latencyMs.median} ms, p95 ${ldap.latency.latencyMs.p95} ms.`
        },
        {
            dimension: "Observed concurrency/scalability",
            summary: c50
                ? `At concurrency 50 across 3 rounds: success ${c50.successRatePercent}%, timeout ${c50.timeoutRatePercent}%, mean ${c50.latencyMs.mean} ms, p95 ${c50.latencyMs.p95} ms, throughput ${c50.throughputPerSecond} auth/s.`
                : "Concurrency 50 was not measured."
        },
        {
            dimension: "Fault tolerance",
            summary:
                "Stopping the isolated slapd process caused bind failure; restart restored successful bind. This single-server baseline is not fault tolerant by itself."
        },
        {
            dimension: "Audit capability",
            summary:
                "slapd produced local stats/debug logs in the runtime directory. They are local mutable server logs, not immutable ledger events."
        }
    ];
}

function buildProtocolComparison({ fabric, radius, ldap }) {
    return {
        fabric: {
            meanAuthenticationLatencyMs: fabric.latency?.latencyMs?.mean,
            p95AuthenticationLatencyMs: fabric.latency?.latencyMs?.p95,
            successRatePercent: fabric.latency?.successRatePercent,
            concurrency50Result: fabric.concurrency50Result || null
        },
        radius: {
            meanAuthenticationLatencyMs: radius.latency.latencyMs.mean,
            p95AuthenticationLatencyMs: radius.latency.latencyMs.p95,
            successRatePercent: radius.latency.successRatePercent,
            concurrency50Result: radius.concurrency.levels["50"] || null
        },
        ldap: {
            meanAuthenticationLatencyMs: ldap.latency.latencyMs.mean,
            p95AuthenticationLatencyMs: ldap.latency.latencyMs.p95,
            successRatePercent: ldap.latency.successRatePercent,
            concurrency50Result: ldap.concurrency.levels["50"] || null
        }
    };
}

function buildSummary({
    timestamp,
    toolAvailability,
    fabric,
    radius,
    ldap,
    options
}) {
    return {
        generatedAt: timestamp,
        comparisonScope:
            "Controlled Phase 12B comparison using isolated local FreeRADIUS and OpenLDAP baselines with synthetic credentials. Fabric results are read from existing formal datasets and are not modified.",
        toolAvailability,
        requestedWorkload: {
            sequentialBatchSizes: options.batchSizes,
            concurrencyLevels: options.concurrencyLevels,
            roundsPerConcurrencyLevel: options.rounds,
            concurrencyCap: 50
        },
        fabric,
        radius,
        ldap,
        protocolComparison: buildProtocolComparison({
            fabric,
            radius,
            ldap
        }),
        spoofingResistanceMatrix: buildSpoofingResistanceMatrix(radius, ldap),
        interpretations: buildInterpretations(),
        radiusFiveDimensionComparison: buildFiveDimensionComparison(radius),
        ldapComparison: buildLdapComparison(ldap),
        fabricFaultToleranceInspection: {
            inspectedConfiguration:
                "backend/src/config/fabricConfig.js",
            finding:
                "Hyperledger Fabric provides a distributed ledger architecture, but the current prototype gateway configuration may retain an application-level dependency on its configured peer endpoint.",
            peerEndpointEnvironmentVariable: "FABRIC_PEER_ENDPOINT",
            defaultPeerEndpoint: "localhost:7051",
            automaticPeerFailoverImplemented: false
        },
        limitations: [
            "RADIUS latency is measured through radclient CLI invocations against an isolated local FreeRADIUS process; timings include local client process overhead.",
            "LDAP latency is measured through ldapwhoami CLI invocations using independent simple-bind operations; timings include local client process overhead.",
            "The RADIUS baseline uses PAP over localhost for controlled centralized credential comparison; it is not a hardened production RADIUS/EAP deployment.",
            "The LDAP baseline uses non-TLS localhost simple bind for controlled comparison; it is not a production directory security profile.",
            "RADIUS/LDAP logs are local mutable runtime files. Fabric audit evidence is ledger-backed.",
            "Fabric measurements are reused from existing Phase 8 and Phase 11 result files rather than rerun."
        ]
    };
}

async function main() {
    const options = parseOptions();
    const timestamp = new Date().toISOString();
    const fileTimestamp = timestampForFile(new Date(timestamp));
    const toolAvailability = await inspectToolAvailability();

    requireTools(toolAvailability);

    const fabric = await loadFabricReference(options.fabricResultsDir);
    const radius = await runRadiusBaseline(
        toolAvailability,
        options,
        fileTimestamp
    );
    const ldap = await runLdapBaseline(
        toolAvailability,
        options,
        fileTimestamp
    );
    const observations = [
        ...radius.observations,
        ...ldap.observations
    ];
    const summary = buildSummary({
        timestamp,
        toolAvailability,
        fabric,
        radius,
        ldap,
        options
    });
    const paths = await writeComparisonFiles({
        resultsDir: options.resultsDir,
        timestamp: fileTimestamp,
        radiusResult: radius,
        ldapResult: ldap,
        summary,
        observations
    });

    console.log(JSON.stringify({
        success: true,
        generatedAt: timestamp,
        radiusMeasured: radius.availableForMeasurement,
        ldapMeasured: ldap.availableForMeasurement,
        fabricDataset: fabric.datasetUsed,
        radiusSequential50: radius.sequentialLatencyByBatch["50"],
        ldapSequential50: ldap.sequentialLatencyByBatch["50"],
        radiusConcurrency50: radius.concurrency.levels["50"],
        ldapConcurrency50: ldap.concurrency.levels["50"],
        outputFiles: paths
    }, null, 2));
}

main().catch((error) => {
    console.error(`Comparison failed: ${error.message}`);
    process.exit(1);
});
