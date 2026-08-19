# Final Implementation-to-Requirements Audit

Phase 14 audit date: 2026-08-19.

This audit compares the current repository implementation against the approved
project baseline supplied for Phase 14 and the repository-level `AGENTS.md`.
It is analysis only. No production source code or chaincode was modified for
this phase.

Status summary:

| Status | Count |
| --- | ---: |
| PASS | 65 |
| PARTIAL | 9 |
| NOT_IMPLEMENTED | 5 |
| DOCUMENTATION_ALIGNMENT | 3 |
| NOT_APPLICABLE | 2 |
| Total audited | 84 |

## Compliance Matrix

| Requirement | Source | Implementation Evidence | Status | Notes / Gap | Recommended Action |
| --- | --- | --- | --- | --- | --- |
| Decentralized device identity and DID-based authentication | Core objective 1 | Device client creates `did:fabric:<uuid>` identities; backend validates DID format; Fabric stores identities; `/api/auth/challenge` and `/api/auth/verify` use DID. | PASS | Implemented as project-specific Fabric DID-like identifiers. | Keep final wording precise: DID-like `did:fabric` identifiers, not a registered W3C DID method. |
| Smart-contract access control and identity validation | Core objective 2 | `AccessControlContract.VerifyAuthentication` checks device existence, ACTIVE status, public key, signature, spoofing classification, and records a ledger event. | PASS | Gateway calls Fabric rather than making the final decision alone. | Retain this architecture in final report. |
| MAC spoofing prevention | Core objective 3 | `spoofingService.evaluateSpoofing` compares registered and observed MAC values; Phase 8 reports 100% spoofing detection. | PASS | Production MAC observation depends on neighbor-table visibility; controlled tests use simulation headers. | Document this as gateway-level network-context enforcement in the prototype. |
| IP spoofing prevention | Core objective 4 | `spoofingService.evaluateSpoofing` compares registered and observed IP values; Phase 8 includes IP spoof cases. | PASS | Same simulation caveat as MAC checks. | Keep simulation and deployment assumptions explicit. |
| Security, latency, and reliability evaluation | Core objective 5 | `evaluation/results/evaluation-summary-2026-08-19T10-30-02-510Z.json` and `concurrency-summary-2026-08-19T12-18-24-016Z.json`. | PASS | Formal local prototype measurements exist. | Use the canonical figures in this audit. |
| Comparison with centralized authentication systems | Core objective 6 | `comparison/results/comparison-summary-2026-08-19T13-28-31-484Z.json` covers isolated FreeRADIUS and OpenLDAP. | PASS | Baselines are local, isolated, synthetic, and intentionally narrower than Fabric. | Do not present as production RADIUS/EAP or production LDAP security profiles. |
| Ethereum versus Hyperledger Fabric benchmarking | Core objective 7 | `ethereum-benchmark/results/ethereum-results-2026-08-19T13-53-24-380Z.json` and comparison report. | PASS | Ethereum benchmark is local Hardhat EDR only. | Use for benchmarking discussion only, not as an alternate implementation. |
| Blockchain development environment | Iteration 1 | Fabric channel `mychannel`, chaincode `identityregistry`, and health check ledger evaluation are implemented; direct GetAllDevices succeeded. | PASS | Environment depends on external Fabric samples path configured in backend `.env`. | Keep external Fabric samples out of this repo. |
| DID/device registration | Iteration 1 | `register-device.js`, `POST /api/devices/register`, and `IdentityRegistryContract.RegisterDevice`. | PASS | Registration endpoint remains open to device clients. | Consider controlled enrollment for production. |
| Identity smart contract | Iteration 1 | `IdentityRegistryContract` implements register, get, list, status, suspend, activate, revoke, exists. | PASS | Uses Fabric JavaScript chaincode. | No immediate change required. |
| Authentication gateway connectivity | Iteration 1 | `fabricService` uses reusable Fabric Gateway/gRPC connection and `/api/health` performs `GetAllDevices`. | PASS | Single configured peer endpoint. | Do not overstate failover. |
| Nonce challenge-response | Iteration 2 | `challengeService` generates UUID challenge IDs, 32-byte crypto nonces, TTL, deterministic payload, single-use consumption. | PASS | In-memory store resets on backend restart, causing outstanding challenges to fail closed. | Redis or durable cache is a future scaling refinement. |
| Smart-contract authentication | Iteration 2 | `/api/auth/verify` submits `VerifyAuthentication` to `AccessControlContract`. | PASS | Authentication result comes from Fabric transaction result. | Preserve contract-backed decision flow. |
| Device signature verification against blockchain public key | Iteration 2 | `AccessControlContract._verifySignature` verifies ECDSA SHA-256 signature using device public key stored in the Fabric device record. | PASS | Backend helper `signatureService.js` is currently unused. | Optionally remove or repurpose unused helper later. |
| MAC spoof detection | Iteration 2 | MAC mismatch scenarios produce `MAC_MISMATCH` and HTTP 403. | PASS | Measured by Phase 8 and attack simulation. | Document controlled simulation input method. |
| IP spoof detection | Iteration 2 | IP mismatch scenarios produce `IP_MISMATCH` and HTTP 403. | PASS | Measured by Phase 8 and attack simulation. | Document controlled simulation input method. |
| Revocation | Iteration 2 | `RevokeDevice` sets status `REVOKED`; challenge endpoint rejects revoked DIDs; `VerifyAuthentication` denies non-ACTIVE devices. | PASS | Targeted Phase 14 restart test confirmed challenge denial after fresh gateway startup. | Keep using ledger status as source of truth. |
| Immutable authentication audit logging | Iteration 3 | `AccessControlContract` stores `AUTH_EVENT` records and emits `AuthenticationEventRecorded`. | PARTIAL | Verification outcomes are audited, but challenge-stage SUSPENDED/REVOKED denials are not currently audit events. | Either audit challenge-stage denials or document the boundary clearly. |
| Administrator dashboard | Iteration 3 | `dashboard/src/App.jsx` implements login, overview, devices, audit, alerts, and performance views. | PASS | Dashboard calls backend API, not Fabric directly. | No immediate redesign required. |
| Spoofing alerts | Iteration 3 | Spoofing Alerts view filters `MAC_MISMATCH`, `IP_MISMATCH`, `MAC_AND_IP_MISMATCH` audit records. | PARTIAL | Alerts exist, but rely on manual refresh and current badge colors use red for spoofing. | Add polling/SSE/WebSocket and amber styling if final UI requirement is strict. |
| Real-time or near-real-time dashboard alert behavior | Iteration 3 | Dashboard has a refresh button and refreshes after device actions. | PARTIAL | No polling interval, server-sent events, WebSocket, or push channel is implemented. | Implement lightweight polling or document manual-refresh behavior. |
| Off-chain storage for sensitive data with on-chain hash/reference design | Iteration 3 | Fabric device records store DID, public key, owner, registered MAC, registered IP, status, timestamps, Fabric IDs. | PARTIAL | This conflicts with the privacy/storage architecture if SDS requires sensitive data off-chain with only hashes/references on-chain. | Treat as a critical alignment item: refactor storage or revise documentation honestly. |
| Spoofing security simulation | Iteration 4 | `attacks/simulation` harness and latest summary show 8/8 passed, 100% detection, 0% false positives. | PASS | Controlled simulation, not packet-level network attack tooling. | Use precise wording in final report. |
| Authentication latency evaluation | Iteration 4 | Phase 8 mixed-scenario mean total auth latency 1895.157 ms; Phase 11 concurrency-1 legitimate mean 2202.725 ms. | PASS | These are different datasets and should not be averaged together. | Use metric-specific labels. |
| Throughput evaluation | Iteration 4 | Phase 11 reports 50-concurrent throughput 27.829 auth/s. | PASS | End-to-end local prototype throughput, not Fabric maximum. | Use Phase 11 for throughput tables. |
| Success rate evaluation | Iteration 4 | Phase 8 and Phase 11 report 100% success where success is expected. | PASS | RADIUS concurrency 25 had 98.67% in its baseline. | Keep per-system rates separate. |
| False positive and false negative evaluation | Iteration 4 | Phase 8: false positive 0%, false negative 0%. | PASS | Based on controlled legitimate and spoofing scenarios. | Use Phase 8 for security-rate table. |
| 50 concurrent request test | Iteration 4 | Phase 11: 150 attempts across 3 rounds at level 50, 100% success, 0 timeouts. | PASS | Uses one registered cryptographic identity to generate 50 concurrent virtual flows. | Do not claim 50 physical devices. |
| RADIUS comparison | Iteration 4 | FreeRADIUS 3.2.10 local baseline; latency/concurrency/outage tests recorded. | PASS | PAP over localhost, not hardened production RADIUS/EAP. | Preserve limitations. |
| LDAP comparison | Iteration 4 | OpenLDAP/slapd 2.6.13 local simple-bind baseline; latency/concurrency/outage tests recorded. | PASS | Non-TLS localhost simple bind for controlled comparison. | Preserve limitations. |
| Ethereum benchmark | Iteration 4 | Hardhat EDR benchmark executed with Solidity contract and generated reports. | PASS | Local automining benchmark only. | Do not generalize to public Ethereum. |
| System refinement based on findings | Iteration 4 | Health check, HTTPS, dashboard performance view, comparison reports, and Ethereum limitations were added in prior phases. | PARTIAL | Final audit findings have not yet been implemented, by instruction. | Prioritize gaps listed below before final submission or document limitations. |
| Authentication <= 5 seconds | Non-functional | Phase 11 50-concurrent mean 1666.532 ms and p95 1834.792 ms. | PASS | Phase 8 mixed mean 1895.157 ms also passes. | Use Phase 11 for concurrency performance claim. |
| 50 concurrent authentication requests | Non-functional | Phase 11: 150/150 successful at concurrency 50, 0 timeouts. | PASS | Virtual concurrent flows from one registered identity. | State scope accurately. |
| Spoof detection <= 3 seconds | Non-functional | Phase 8 average spoofing check 0.054 ms; Phase 11 50-concurrent mean 0.039 ms. | PASS | Measures comparison logic duration returned by backend. | Use Phase 8 for security evaluation and Phase 11 for load context. |
| False positive rate below 5% | Non-functional | Phase 8 false positive rate 0%. | PASS | Controlled dataset. | Include formula from evaluation README. |
| Revoked-device denial after gateway restart | Non-functional | Phase 14 targeted test: fresh backend on port 3098 returned HTTP 403 for revoked DID. | PASS | Tested against existing revoked ledger identity without modifying Fabric. | Keep curl evidence below. |
| HTTPS/TLS | Non-functional | Backend can start HTTP and HTTPS; Phase 11 evaluator requires HTTPS with CA; dashboard README documents HTTPS setup. | PASS | `.env.example` defaults `HTTPS_ENABLED=false` for local development. | Enable HTTPS in final demo/production config. |
| Private key never transmitted | Non-functional | Device client reads `private-key.pem` locally; registration sends public key; authentication sends challenge ID and signature only. | PASS | `.gitignore` excludes generated device credentials and `*.pem`. | Continue avoiding private-key output/logging. |
| Bcrypt admin password hashing | Non-functional | `adminStore.createAdmin` uses `bcrypt.hash` with cost 12; README says JSON store contains hashes only. | PASS | `backend/data/admins.json` is ignored. | No immediate change required. |
| RBAC | Non-functional | Backend protects device list/detail/audit/performance for ADMIN or VIEWER and status mutations for ADMIN only; smoke test checks VIEWER buttons. | PASS | `POST /api/devices/register` is intentionally still unauthenticated for device enrollment. | Review enrollment authorization before production. |
| GREEN for granted | Dashboard/usability | `.decision-GRANTED` uses green colors. | PASS | Visual evidence in CSS. | No change required. |
| RED for denied | Dashboard/usability | `.decision-DENIED` uses red colors. | PASS | Visual evidence in CSS. | No change required. |
| AMBER for suspicious/spoofing | Dashboard/usability | `.spoofing-CONTEXT_INCOMPLETE` is amber, but MAC/IP mismatch spoofing classes are red. | PARTIAL | Requirement asks amber for suspicious/spoofing. | Change spoofing mismatch badge palette to amber if required. |
| Human-readable audit event descriptions | Dashboard/usability | Audit table displays reason codes such as `VALID_SIGNATURE`, `MAC_MISMATCH`. | PARTIAL | Codes are understandable to developers but not human-readable prose. | Add display label mapping while preserving raw code if needed. |
| Authentication/audit monitoring | Dashboard/usability | Overview and Authentication Audit view fetch immutable events from `/api/audit/authentication`. | PASS | Requires admin session. | No immediate change required. |
| Spoofing alerts view | Dashboard/usability | Spoofing Alerts view filters mismatch events. | PASS | Alert freshness is manual refresh. | Combine with near-real-time remediation if needed. |
| Device management | Dashboard/usability | Devices view supports list, details, suspend, activate, revoke for ADMIN. | PASS | Registration is not in dashboard. | Add registration UI only if final scope requires it. |
| Performance view | Dashboard/usability | Performance view displays live metrics and formal Phase 11 results. | PASS | Live metrics reset on backend restart. | Document live versus formal metrics. |
| ADMIN/VIEWER controls | Dashboard/usability | Role pill, backend role middleware, and dashboard smoke-test role assertions. | PASS | UI hides privileged buttons for VIEWER; backend enforces status mutations. | No immediate change required. |
| Fabric chaincode input validation | Smart contract quality | `_requireValue`, decision/classification validation, boolean parsing, and non-empty checks. | PASS | DID format itself is enforced in backend, not chaincode. | Consider chaincode DID format validation if contract may be invoked directly. |
| Fabric duplicate protection | Smart contract quality | Duplicate device and duplicate authentication event IDs are rejected. | PASS | Covered in AccessControlContract tests. | No immediate change required. |
| Fabric access authorization | Smart contract quality | Gateway/admin middleware protects selected REST operations; chaincode records Fabric client identity. | PARTIAL | Chaincode does not enforce fine-grained MSP attribute roles; most submits use Org1 User1 through gateway. | Add chaincode-level client identity/attribute policy if SDS requires smart-contract authorization. |
| Fabric immutable audit behavior | Smart contract quality | Auth events are written under composite keys and duplicate event IDs rejected. | PASS | Fabric state can be superseded only by new keys; Fabric history provides immutability semantics. | No immediate change required. |
| Fabric cryptographic handling | Smart contract quality | Node `crypto.createVerify("SHA256")` verifies P-256 public-key signatures; nonce consumption is in gateway. | PASS | Challenge payload/signature are not stored in audit records. | Keep exact payload contract stable. |
| NatSpec for Fabric JavaScript | Smart contract quality | Fabric chaincode uses JSDoc-style comments. | NOT_APPLICABLE | NatSpec is Solidity-specific, not a JavaScript chaincode standard. | Use JSDoc/comments for Fabric documentation. |
| Ethereum input validation | Smart contract quality | Solidity `require` checks DID, publicKeyReference, owner, event ID, reason, device existence. | PASS | DID syntax is not validated beyond non-empty. | Optional stricter validation would increase gas and complexity. |
| Ethereum duplicate protection | Smart contract quality | Duplicate device status and duplicate event IDs rejected in contract/tests. | PASS | Tests cover both cases. | No immediate change required. |
| Ethereum access authorization | Smart contract quality | `onlyAdministrator` and `onlyRecorder` modifiers. | PASS | Authorized recorder support was added for concurrent benchmark accounts. | No immediate change required. |
| Ethereum immutable audit behavior | Smart contract quality | `recordAuthenticationDecision` stores events by event ID and appends event keys. | PASS | Benchmark does not expose mutation of prior events. | No immediate change required. |
| Ethereum arithmetic/reentrancy/external-call risks | Smart contract quality | Solidity 0.8 checked arithmetic, no Ether handling, no external calls, no reentrancy surface observed. | PASS | Arrays can grow; acceptable for local benchmark but not production pagination. | Document benchmark scope. |
| Ethereum NatSpec documentation | Smart contract quality | `AuthenticationBenchmark.sol` has no `///` or `/** */` NatSpec comments. | PARTIAL | Functional tests pass, but documentation requirement is not met. | Add NatSpec comments before final submission if Solidity artifact is included. |
| Solidity static-analysis scanner | Smart contract quality | `slither` was not found locally. | NOT_APPLICABLE | No scanner was run and none was installed during Phase 14. | State "manual review only" unless a scanner is later run. |
| `did:fabric:<identifier>` standard alignment | Identity standard alignment | Source only validates the string pattern and stores it as an identifier. | DOCUMENTATION_ALIGNMENT | This is project-specific DID-like syntax, not a fully registered/resolvable DID method. | Phrase final report as "DID-like decentralized identifier used by the prototype." |
| DID Documents | Identity standard alignment | No DID Document schema, storage, or endpoint found. | NOT_IMPLEMENTED | Device records are not DID Documents. | Do not claim DID Documents unless implemented. |
| DID resolution | Identity standard alignment | No resolver interface or DID resolution process found. | NOT_IMPLEMENTED | Backend directly queries Fabric by DID. | Describe as Fabric identity lookup, not DID resolution. |
| Verifiable Credentials | Identity standard alignment | No VC issuance, presentation, verification, or schemas found. | NOT_IMPLEMENTED | Out of current implementation. | Do not claim VC support. |
| REST communication stack | Communication stack | Backend exposes Express REST API; device client and dashboard use REST/HTTPS. | PASS | Matches actual implementation. | Use REST/HTTPS wording. |
| MQTT communication stack | Communication stack | No MQTT dependency, broker, topic handling, or client code found. | NOT_IMPLEMENTED | Appears to be an option in documentation, not implemented. | Mark MQTT as not implemented unless a later phase adds it. |
| Fabric ledger distribution | Fault tolerance | Fabric network has orderer, peers, and ledger replication outside this repo. | PASS | Blockchain ledger distribution exists at Fabric level. | Explain as ledger-level resilience. |
| Application-level peer failover | Fault tolerance | `fabricConfig.peerEndpoint` points to one configured peer endpoint; `fabricService` holds one gRPC client. | NOT_IMPLEMENTED | No peer rotation/failover policy in gateway. | Do not claim gateway connection redundancy; add multi-peer failover later if required. |
| "Blockchain removes single points of failure" wording | Fault tolerance | Fabric is distributed, but gateway and configured peer endpoint remain application dependencies. | DOCUMENTATION_ALIGNMENT | Ledger distribution and gateway availability are different. | Revise final claims to say SPOF is reduced at ledger layer, not eliminated end to end. |
| Ethereum remains benchmarking-only | Ethereum comparison | `ethereum-benchmark` is separate; README says it does not replace Fabric implementation. | PASS | Backend/dashboard do not call Ethereum. | Keep Ethereum section isolated as comparison. |
| Local Hardhat EDR and automining limitations | Ethereum comparison | Results identify Hardhat 3.13.0, chainId 31337, local simulated L1, automining. | DOCUMENTATION_ALIGNMENT | Not public network performance. | State results are local deterministic benchmark observations. |
| No public Ethereum testnet/Mainnet/real ETH | Ethereum comparison | Result says public testnet not performed; gas cost is simulated. | PASS | No public RPC/test ETH configured. | Do not claim real ETH was spent or Mainnet/testnet behavior measured. |
| Actual isolated FreeRADIUS experiment | RADIUS/LDAP | Comparison summary lists FreeRADIUS 3.2.10, `radclient`, isolated localhost port 18120. | PASS | Runtime secrets generated under ignored directory. | No change required. |
| Actual isolated slapd experiment | RADIUS/LDAP | Comparison summary lists OpenLDAP/slapd 2.6.13 and `ldapwhoami`, localhost port 1389. | PASS | LDAP simple bind without TLS for controlled local baseline. | No change required. |
| RADIUS/LDAP latency measurements | RADIUS/LDAP | RADIUS mean 35.168 ms over 85 observations; LDAP mean 12.454 ms over 85 observations. | PASS | CLI overhead included. | Preserve limitation in report. |
| RADIUS/LDAP concurrency measurements | RADIUS/LDAP | Concurrency levels 1, 10, 25, 50 recorded for both systems. | PASS | RADIUS level 25 had 98.67% success; level 50 had 100%. | Report per level, not a single blended result. |
| RADIUS/LDAP fault availability experiment | RADIUS/LDAP | Reports include outage/restart behavior for isolated FreeRADIUS and slapd. | PASS | Single-server baselines fail during outage and recover after restart. | Use as centralized availability comparison. |
| Static credential reuse wording | RADIUS/LDAP | Reports say repeated valid credentials were accepted as expected and not packet replay. | PASS | This is correctly framed. | Preserve "static credential reuse" terminology. |
| Canonical results inventory | Results consistency | This audit lists Phase 8, Phase 11, Phase 12B, and Phase 13 canonical files and figures. | PASS | Avoids stale/intermediate runs. | Use file names below in final report. |
| Metric selection by table | Results consistency | This audit distinguishes mixed-scenario mean, legitimate concurrency-1 mean, and 50-concurrent mean. | PASS | Incompatible datasets are not averaged. | Follow the guidance in "Canonical evaluation figures." |
| Avoid silent averaging of incompatible datasets | Results consistency | No new aggregate was calculated by mixing Fabric, RADIUS, LDAP, and Ethereum scopes. | PASS | Ethereum measures transaction writes, not full auth. | Keep comparisons scoped by operation type. |

## Critical Gaps Before Submission

1. Privacy/storage architecture mismatch: Fabric currently stores owner, MAC,
   IP, and public key directly in device records. If the SDS/proposal requires
   off-chain sensitive data with on-chain hashes/references, this must be fixed
   or documented as an intentional prototype deviation.
2. Standards wording: `did:fabric:<identifier>` is a project-specific DID-like
   identifier. The implementation does not include DID Documents, DID
   resolution, or Verifiable Credentials.
3. Fault tolerance wording: Fabric ledger distribution exists, but the gateway
   uses one configured peer endpoint and does not implement application-level
   peer failover.
4. Smart-contract authorization scope: Fabric chaincode validates data and
   records client identity, but it does not enforce fine-grained chaincode role
   policy. Backend RBAC protects dashboard operations, while device
   registration remains open for enrollment.

## Minor Gaps

1. Dashboard spoofing mismatch badges are red, while the requirement asks for
   amber suspicious/spoofing indication.
2. Dashboard audit reasons are raw codes rather than human-readable prose.
3. Dashboard alert behavior is manual refresh, not automatic near-real-time
   polling or push.
4. `backend/src/services/signatureService.js` is currently unused because final
   verification occurs in `AccessControlContract`.
5. Challenge storage is in-memory. This fails closed on backend restart but
   invalidates outstanding legitimate challenges.
6. Suspended/revoked challenge-stage denials are not immutable audit events.

## Documentation-Only Corrections

1. Do not claim public Ethereum, testnet, or Mainnet performance. Phase 13 used
   local Hardhat EDR with automining and simulated gas.
2. Do not call RADIUS/LDAP static credential reuse a packet replay attack.
3. Do not claim MQTT is implemented. The working communication stack is
   REST/HTTPS.
4. Do not claim 50 physical devices were tested. Phase 11 used 50 concurrent
   virtual authentication flows from one registered cryptographic identity.
5. Do not claim the current Fabric storage design already implements the
   off-chain hash/reference privacy architecture.
6. Do not claim blockchain removes every single point of failure in the full
   application path.

## Requirements Already Satisfied

- Fabric device identity lifecycle: register, list, get, suspend, activate,
  revoke, and existence checks.
- Nonce challenge-response with cryptographically random nonces and single-use
  challenge consumption.
- Device-side ECDSA P-256 signing with private keys kept locally.
- Backend verification through Fabric `AccessControlContract`.
- Ledger-backed authentication audit events for verification outcomes.
- MAC/IP spoofing classification and denial in controlled prototype tests.
- Admin login, bcrypt password hashing, cookie sessions, and ADMIN/VIEWER RBAC.
- Dashboard monitoring for devices, audit events, spoofing alerts, and
  performance metrics.
- Formal Fabric security/performance evaluation, concurrency evaluation,
  RADIUS/LDAP comparison, and Ethereum local benchmark.

## On-Chain Storage Privacy Review

### A. What Is Currently On-Chain

Fabric `IdentityRegistryContract.RegisterDevice` stores these fields in
`DEVICE` records:

- `docType`
- `did`
- `publicKey`
- `owner`
- `registeredMacAddress`
- `registeredIpAddress`
- `status`
- `registeredAt`
- `updatedAt`
- `revokedAt`
- `revocationReason`
- `suspensionReason` when suspended
- `createdBy`
- `updatedBy`
- `transactionId`
- `lastTransactionId`

Fabric `AccessControlContract` stores authentication audit events with:

- `docType`
- `eventId`
- `did`
- `timestamp`
- `decision`
- `reason`
- `observedMacAddress`
- `observedIpAddress`
- `spoofingClassification`
- `recordedBy`
- `transactionId`

It intentionally does not store `challengePayload` or `signature` in audit
events.

### B. What Documentation Says Should Be On-Chain

The Phase 14 baseline says the documented privacy/storage architecture should
use off-chain storage for sensitive data with on-chain hashes/references.
Under that model, the ledger should hold only the minimum information needed
for integrity, identity state, and auditability, such as DID, status, hashes,
references, timestamps, and transaction metadata.

### C. Privacy Implications

- MAC address, IP address, and owner values are operational identifiers and may
  be sensitive in a network-authentication context.
- Once written to Fabric, values remain visible to authorized ledger
  participants and may remain in history even if later updated.
- Public keys are not private secrets, but they are stable correlators.
- Observed MAC/IP values in authentication events create a persistent
  authentication-location/context trail.

### D. Smallest Reasonable Remediation

The smallest code remediation is to introduce an off-chain metadata store behind
the backend service layer and update Fabric records to store only:

- `did`
- status and revocation state
- public-key hash or public-key reference
- salted/HMAC metadata hashes or references for MAC/IP/owner
- timestamps and Fabric transaction metadata

Signature verification would then need a safe design for retrieving the public
key off-chain and proving that it matches the on-chain hash/reference. Spoofing
comparison would likewise use backend/off-chain metadata, not raw MAC/IP values
read from the ledger.

### E. Documentation Revision Alternative

If the prototype intentionally stores public key, owner, MAC, and IP on Fabric
for inspectability and simpler chaincode verification, the final documentation
should state this as an implementation refinement/limitation. It should not
claim that the Fabric implementation already follows the off-chain
hash/reference architecture.

## Canonical Evaluation Figures

Use these files as the canonical final result inventory:

- Fabric Phase 8 security/performance:
  `evaluation/results/evaluation-summary-2026-08-19T10-30-02-510Z.json`
- Fabric Phase 11 concurrency:
  `evaluation/results/concurrency-summary-2026-08-19T12-18-24-016Z.json`
- RADIUS/LDAP Phase 12B:
  `comparison/results/comparison-summary-2026-08-19T13-28-31-484Z.json`
- Ethereum Phase 13:
  `ethereum-benchmark/results/ethereum-results-2026-08-19T13-53-24-380Z.json`
  and
  `ethereum-benchmark/results/ethereum-fabric-comparison-2026-08-19T13-53-24-380Z.json`

Recommended metric usage:

| Report table | Recommended metric | Why |
| --- | --- | --- |
| Fabric security outcomes | Phase 8 security summary | It includes legitimate, spoofing, invalid signature, replay, suspended, and revoked scenarios. |
| Fabric single legitimate latency | Phase 11 concurrency-1 mean 2202.725 ms, p95 2210.952 ms | It measures full legitimate HTTPS authentication with challenge, signing, verify, audit correlation. |
| Fabric mixed-scenario latency | Phase 8 average total authentication duration 1895.157 ms | It summarizes mixed security scenarios and should not be labeled as pure legitimate latency. |
| Fabric 50-concurrent capacity | Phase 11 level 50 mean 1666.532 ms, p95 1834.792 ms, throughput 27.829 auth/s | It directly addresses the 50-concurrent requirement. |
| Fabric spoofing speed | Phase 8 average spoofing check 0.054 ms, or Phase 11 level 50 mean 0.039 ms for load context | Both are far below 3 seconds but measure the comparison logic, not packet capture. |
| RADIUS latency comparison | Phase 12B RADIUS mean 35.168 ms, median 33.867 ms, p95 44.023 ms | 85 isolated local FreeRADIUS observations. |
| LDAP latency comparison | Phase 12B LDAP mean 12.454 ms, median 11.326 ms, p95 16.982 ms | 85 isolated local slapd simple-bind observations. |
| RADIUS 50 concurrency | Mean 505.556 ms, p95 873.77 ms, throughput 58.522 auth/s, success 100% | Local single-server FreeRADIUS baseline. |
| LDAP 50 concurrency | Mean 155.502 ms, p95 256.723 ms, throughput 168.502 auth/s, success 100% | Local single-server slapd baseline. |
| Ethereum transaction benchmark | Hardhat level 50 mean 327.673 ms, p95 617.172 ms, throughput 147.42 tx/s | Transaction/event benchmark only, not full authentication. |

Key measured figures:

- Phase 8 security: spoofing detection 100%, false positive 0%, false negative
  0%, auth success 100%, replay rejection 100%, invalid signature rejection
  100%, suspended rejection 100%, revoked rejection 100%.
- Phase 8 performance: challenge 28.419 ms, signing 0.996 ms, verification
  2131.473 ms, spoofing check 0.054 ms, total 1895.157 ms.
- Phase 11 concurrency 50: 150 attempts, 100% success, 0 timeouts, mean
  1666.532 ms, median 1728.42 ms, p95 1834.792 ms, throughput 27.829 auth/s,
  audit correlation 100%.
- RADIUS overall latency: mean 35.168 ms, median 33.867 ms, p95 44.023 ms.
- LDAP overall latency: mean 12.454 ms, median 11.326 ms, p95 16.982 ms.
- Ethereum deployment gas: 1,390,917 gas; authentication-event gas mean
  237,321.414; public testnet not performed.

## Revoked-After-Restart Test Evidence

The exact non-functional requirement for revoked-device denial after
backend/gateway restart was tested during Phase 14 with an existing revoked DID
and a fresh backend process on port 3098. No ledger mutation was performed.

Command:

```sh
PORT=3098 HTTPS_ENABLED=false ALLOW_SIMULATED_NETWORK_CONTEXT=true \
ADMIN_SESSION_SECRET=phase14-local-secret-12345678901234567890 \
node src/server.js
```

Health check:

```sh
curl -s -i http://localhost:3098/api/health
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"success":true,"api":"healthy","fabric":"connected"}
```

Revoked challenge request:

```sh
curl -s -i -X POST http://localhost:3098/api/auth/challenge \
  -H 'Content-Type: application/json' \
  -d '{"did":"did:fabric:7d4e4be5-5ea3-41a0-ad48-fc5836540507"}'
```

Response:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8

{"success":false,"message":"Revoked devices cannot receive authentication challenges"}
```

Conclusion: revoked-device enforcement survives gateway restart because the
fresh backend reads status from the Fabric ledger.

## Claims That Must NOT Be Made

- The prototype fully implements W3C DID, DID Documents, DID resolution, or
  Verifiable Credentials.
- MQTT is implemented.
- Ethereum benchmark results represent public Ethereum testnet or Mainnet
  performance.
- Real ETH was spent.
- Hardhat simulated gas is the same as production transaction cost.
- The Fabric gateway has application-level multi-peer failover.
- Blockchain removes all single points of failure in the complete deployed
  application.
- RADIUS/LDAP static credential reuse is packet replay.
- The 50-concurrent Fabric test used 50 separate physical devices.
- Current Fabric identity records implement off-chain sensitive-data storage
  with only on-chain hashes/references.
- Challenge issuance by itself means authentication is granted.

## Recommended Final Development Actions

1. Resolve the Fabric privacy/storage mismatch: either refactor to off-chain
   sensitive metadata with on-chain hashes/references, or explicitly document
   the current ledger schema as a prototype limitation.
2. Add automatic dashboard refresh or event streaming for near-real-time
   spoofing alerts.
3. Add human-readable audit labels and amber spoofing badge styling.
4. Decide whether suspended/revoked challenge-stage denials should be written
   as immutable audit events.
5. Add chaincode-level authorization checks if the final SDS requires smart
   contract enforcement of admin roles rather than gateway-only RBAC.
6. Add NatSpec comments to `ethereum-benchmark/contracts/AuthenticationBenchmark.sol`.
7. Document DID standard alignment precisely and remove any unsupported claims
   about DID Documents, DID resolution, or Verifiable Credentials.
8. Add gateway multi-peer failover only if the final fault-tolerance claim
   requires it.
