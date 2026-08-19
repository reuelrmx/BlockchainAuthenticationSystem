# Phase 8 Evaluation

This directory contains the formal, repeatable performance and security
evaluation harness for the current Hyperledger Fabric authentication prototype.
It calls the existing REST gateway and audit API; it does not modify
authentication logic, chaincode, dashboard code, or Fabric network state except
for temporary suspension of a non-primary status-test identity.

## Prerequisites

Run the backend with simulation mode enabled before executing the evaluator:

```sh
ALLOW_SIMULATED_NETWORK_CONTEXT=true PORT=3000 npm start
```

The evaluator fails early unless:

- `GET /api/health` reports Fabric as connected.
- the primary test DID is `ACTIVE`.
- the audit API is reachable.
- a legitimate warm-up authentication with simulated registered MAC/IP succeeds.
- the local primary device private key exists.
- `evaluation/results/` is writable.

The primary test device is:

```text
did:fabric:b9f2e316-3d27-4a45-a044-128d760fff26
gateway/device-client/devices/33bad912-4914-449f-b674-7c5fba40d9d8
AA:BB:CC:DD:EE:01
192.168.1.30
```

Private keys are read only for local signing and are never printed or written to
result files.

## Run

```sh
node evaluation/run-evaluation.js
```

Useful options:

```sh
node evaluation/run-evaluation.js --batches 10,25,50 --warmup 3
node evaluation/run-evaluation.js --results-dir evaluation/results
node evaluation/run-evaluation.js --skip-expired-audit-check
```

The default run performs three sequential controlled batches: 10, 25, and 50
iterations. It stops before larger batches if a smaller batch exposes a defect.

## Outputs

Generated files are ignored by Git except for `results/.gitkeep`:

- `evaluation/results/evaluation-10-<timestamp>.json`
- `evaluation/results/evaluation-25-<timestamp>.json`
- `evaluation/results/evaluation-50-<timestamp>.json`
- `evaluation/results/evaluation-summary-<timestamp>.json`
- `evaluation/results/evaluation-observations-<timestamp>.csv`

The CSV columns are suitable for spreadsheet graphs and include timing,
decision, classification, HTTP status, audit event, and pass/fail fields.

## Statistics

Timing metrics use `process.hrtime.bigint()` at the client/evaluator boundary:

- `challengeDurationMs`
- `signingDurationMs`
- `verificationDurationMs`
- `spoofingCheckDurationMs`
- `totalAuthenticationDurationMs`

For each metric, the evaluator calculates count, minimum, maximum, arithmetic
mean, median, sample standard deviation, and nearest-rank p95 when at least two
samples exist. Warm-up attempts are excluded from final statistics.

Security metrics are defined as:

- True positive: spoofing attempt denied with the expected spoofing
  classification.
- False negative: spoofing attempt not denied with the expected spoofing
  classification.
- False positive: legitimate authentication not granted with classification
  `NONE`.
- True negative: legitimate authentication granted with classification `NONE`.

The report also calculates replay, invalid-signature, suspended-device, and
revoked-device rejection rates.

## Audit Completeness

The audit matrix distinguishes verification outcomes from challenge-stage
denials. In the current design, `/api/auth/verify` records authentication
events, while suspended/revoked devices are denied by `/api/auth/challenge`
before a verification attempt exists. The evaluator reports this explicitly as
current behavior rather than changing the logging architecture during Phase 8.
