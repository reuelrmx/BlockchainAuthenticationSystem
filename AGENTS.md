# Blockchain Authentication System — Codex Instructions

## Project

This repository implements the final-year project:

**A Blockchain-Based Secure Network Authentication System Using Smart Contracts and Decentralized Identity**

The primary implementation platform is **Hyperledger Fabric**. Ethereum may later be used only for benchmarking/comparison.

The application is intended to authenticate network devices using decentralized identities, cryptographic challenge-response authentication, blockchain-backed public keys, smart-contract access control, and spoofing detection.

## Architecture

The intended application flow is:

Device Client
→ REST Authentication Gateway
→ Hyperledger Fabric Gateway SDK
→ Smart Contract / Chaincode
→ Hyperledger Fabric Ledger

The administrator dashboard must interact with the backend API rather than directly with Hyperledger Fabric.

## Existing Environment

Hyperledger Fabric samples are installed separately at:

`/home/reuel/blockchain-project/fabric-samples`

The Fabric test network is run from:

`/home/reuel/blockchain-project/fabric-samples/test-network`

Do not copy or restructure the Fabric test network into this repository.

The application repository is:

`/home/reuel/Desktop/BlockchainAuthenticationSystem`

The main Fabric channel is:

`mychannel`

The deployed identity chaincode name is:

`identityregistry`

The Fabric smart contract class is:

`IdentityRegistryContract`

## Completed Work

The following components are already implemented and working.

### Hyperledger Fabric

* Fabric test network successfully configured.
* Org1 and Org2 peers operational.
* Orderer operational.
* Certificate Authorities operational.
* `mychannel` created.
* `identityregistry` chaincode successfully deployed.

### Identity Registry Chaincode

Location:

`blockchain/chaincode/identity-registry`

Implemented transactions include:

* `RegisterDevice`
* `GetDevice`
* `GetAllDevices`
* `GetDeviceStatus`
* `SuspendDevice`
* `ActivateDevice`
* `RevokeDevice`
* `DeviceExists`

Device records contain information including:

* DID
* public key
* owner
* registered MAC address
* registered IP address
* ACTIVE/SUSPENDED/REVOKED status
* registration timestamp
* update timestamp
* revocation information
* Fabric transaction IDs
* Fabric client identity information

### Backend / Authentication Gateway

Location:

`backend`

Implemented using Node.js and Express.

Fabric communication uses:

* `@hyperledger/fabric-gateway`
* `@grpc/grpc-js`
* Org1 `User1` X.509 identity

Existing REST endpoints include:

* `GET /`
* `GET /api/health`
* `GET /api/devices`
* `GET /api/devices/:did`
* `POST /api/devices/register`
* `PATCH /api/devices/:did/suspend`
* `PATCH /api/devices/:did/activate`
* `PATCH /api/devices/:did/revoke`

Fabric connection code is implemented in:

`backend/src/services/fabricService.js`

### Device Client

Location:

`gateway/device-client`

Implemented functionality includes:

* Local ECDSA P-256 key-pair generation.
* SHA-256 signatures.
* Local private-key storage.
* Public-key registration through the REST gateway.
* DID creation using the format `did:fabric:<uuid>`.
* Local `identity.json`.
* Signature generation and verification testing.

Private keys must remain on the device and must never be transmitted to the backend or stored on-chain.

Generated device credentials must not be committed to Git.

## Security Requirements

Do not weaken these constraints:

1. Never transmit device private keys.
2. Never store device private keys on Hyperledger Fabric.
3. Never commit private keys, `.env` files, generated Fabric credentials, or device identity secrets to Git.
4. Authentication must not trust MAC or IP addresses alone.
5. A valid cryptographic signature is required for successful authentication.
6. Revoked devices must always be denied authentication.
7. Suspended devices must be denied authentication.
8. Challenges/nonces must be cryptographically random.
9. Nonces must expire.
10. Nonces must be single-use to prevent replay attacks.
11. Authentication and spoofing events must eventually be auditable.
12. Keep blockchain-specific logic isolated behind the backend/Fabric service layer.

## Project Requirements

The final system is intended to implement:

* Decentralized device identities.
* Blockchain-backed public keys.
* Smart-contract identity management.
* Digital-signature authentication.
* Nonce challenge-response authentication.
* Replay-attack prevention.
* MAC spoofing detection.
* IP spoofing detection.
* Identity revocation.
* Authentication audit logging.
* Administrator monitoring dashboard.
* Security, latency, and reliability evaluation.
* Comparison against traditional centralized authentication.

## Immediate Next Phase

The next subsystem to implement is **challenge-response device authentication**.

Implement it incrementally.

### Phase 1 — Nonce Challenge

Backend endpoint:

`POST /api/auth/challenge`

Input should identify the device by DID.

The backend must:

1. Verify that the DID exists on Fabric.
2. Verify that its status is ACTIVE.
3. Generate a cryptographically secure random nonce.
4. Associate the nonce with that DID.
5. Give the nonce a short expiration time.
6. Store it temporarily.
7. Return the nonce and expiration information.

A challenge must not authenticate the device by itself.

### Phase 2 — Device Signature

Extend the device client so it can:

1. Read its DID from local `identity.json`.
2. Request a challenge from the gateway.
3. Read its local private key.
4. Sign the exact nonce/challenge payload using ECDSA with SHA-256.
5. Send the DID, challenge identifier, and signature to the gateway.

The private key must never be included in the request.

### Phase 3 — Authentication Verification

Backend endpoint:

`POST /api/auth/verify`

The backend must:

1. Locate the challenge.
2. Confirm it belongs to the DID.
3. Confirm it has not expired.
4. Confirm it has not already been used.
5. Query the registered device from Hyperledger Fabric.
6. Confirm the device remains ACTIVE.
7. Retrieve the blockchain-stored public key.
8. Verify the ECDSA signature.
9. Consume the nonce regardless of the final authentication outcome where appropriate to prevent replay.
10. Return GRANTED or DENIED.

### Phase 4 — Authentication Events

After the core flow works, add authentication event recording containing at minimum:

* authentication/event ID
* DID
* timestamp
* outcome
* observed MAC
* observed IP
* reason for denial
* spoofing classification where applicable

Do not implement the dashboard before the authentication flow works.

## Development Rules

* Inspect existing code before modifying it.
* Preserve working functionality unless a change is required.
* Make focused changes rather than large rewrites.
* Explain significant architectural changes.
* Run syntax/tests after modifying JavaScript.
* Test API endpoints using curl where appropriate.
* Check `git diff` before concluding a task.
* Do not use `git push --force`.
* Do not modify the external `fabric-samples` installation unless the task specifically requires Fabric network configuration.
* Do not reset or destroy the Fabric test network without warning because doing so removes the current test ledger and requires chaincode redeployment.
* Prefer built-in Node.js `crypto` functionality rather than adding cryptography dependencies without need.
* Follow the existing file and folder conventions.

## Current Development Priority

Do not jump ahead to dashboard development.

The development order is:

1. Nonce challenge service.
2. Device signing client.
3. Signature verification.
4. Replay protection.
5. Authentication logging.
6. MAC spoofing detection.
7. IP spoofing detection.
8. Smart-contract/audit improvements.
9. Administrator dashboard.
10. Attack simulation and testing.
11. Performance evaluation.

Before implementing a major phase, inspect the current relevant files and state what changes are required.
