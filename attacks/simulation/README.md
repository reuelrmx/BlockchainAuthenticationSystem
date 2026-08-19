# Phase 6 Attack Simulation Harness

This harness runs controlled authentication scenarios against the local project API. It does not perform packet flooding, ARP poisoning, credential theft, denial-of-service testing, or attacks against external hosts.

Run the backend with controlled simulation mode enabled before spoofing tests:

```bash
ALLOW_SIMULATED_NETWORK_CONTEXT=true PORT=3000 node backend/src/server.js
```

Run a single pass:

```bash
node attacks/simulation/run-scenarios.js \
  --api http://localhost:3000 \
  --device gateway/device-client/devices/<device-folder> \
  --iterations 1
```

Run a small batch:

```bash
node attacks/simulation/run-scenarios.js \
  --api http://localhost:3000 \
  --device gateway/device-client/devices/<device-folder> \
  --iterations 5
```

Results are written to `attacks/results/<timestamp>-simulation-results.json` and a companion summary file.

Metrics formulas:

- `detectionAccuracyPercent`: true positives / (true positives + false negatives) * 100, over `MAC_SPOOF`, `IP_SPOOF`, and `MAC_IP_SPOOF`.
- `falsePositiveRatePercent`: legitimate false positives / legitimate authentication attempts * 100, over `LEGITIMATE`.
- `averageAuthenticationLatencyMs`: mean `totalEndToEndAuthenticationDurationMs` across completed, non-skipped results.
- `averageSpoofingCheckMs`: mean API-returned `spoofingCheckDurationMs`, excluding null values.

These prototype runs are functional checks and should not be described as statistically significant.
