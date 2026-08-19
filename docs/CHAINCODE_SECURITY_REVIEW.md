# Chaincode Security Review

Review date: 2026-08-19.

Baseline: 30 May 2026 SDS alignment review of the Fabric JavaScript contracts
in `blockchain/chaincode/identity-registry`.

## Contracts Reviewed

- `IdentityRegistryContract`
- `AccessControlContract`
- `AuditLogContract`

No external static-analysis scanner was run. This is a manual source and test
review against the May-2026 SDS security concerns.

## Findings

| Concern | Review Result | Evidence |
| --- | --- | --- |
| Improper access control | Mitigated for privileged mutations. `RegisterDevice`, `SuspendDevice`, `ActivateDevice`, `RevokeDevice`, and `UpdateAccessPolicy` require a Fabric administrator identity. | `lib/authorization.js`; `IdentityRegistryContract`; `AccessControlContract`; `npm test`. |
| Weak input validation | Partially mitigated. Required fields, SHA-256 hash format, decision values, spoofing classifications, boolean parsing, and policy actions are validated. DID syntax is still primarily enforced in the backend. | `_requireValue`, `_requireSha256Hex`, `_normalizeAccessPolicy`, contract tests. |
| Replay weaknesses | Mitigated at gateway layer, not chaincode. The backend consumes challenges single-use before submitting `VerifyAuthentication`; chaincode rejects duplicate authentication event IDs. | `backend/src/services/challengeService.js`; `authenticationEventExists`. |
| Insecure endorsement assumptions | Documented limitation. The prototype uses the existing Fabric test-network lifecycle and endorsement policy. No custom endorsement policy hardening was added in this phase. | Fabric lifecycle query and deployment commands. |
| Incorrect identity status handling | Mitigated. Verification denies missing, suspended, and revoked/non-ACTIVE devices. | `VerifyAuthentication`; access-control tests. |
| Duplicate state/event creation | Mitigated. Device registration rejects existing DIDs; authentication and generic audit event IDs reject duplicates. | `DeviceExists`; `authenticationEventExists`; `putGenericAuditEvent`; tests. |
| Malformed signatures/keys | Mitigated for verification. Invalid or missing public keys/signatures fail closed as `PUBLIC_KEY_UNAVAILABLE` or `INVALID_SIGNATURE`. | `_verifySignature`; tests for modified payload and wrong key. |
| Unauthorized policy mutation | Mitigated. `UpdateAccessPolicy` uses Fabric-admin authorization and writes a policy audit event. | `AccessControlContract.UpdateAccessPolicy`; tests. |

## Function-Level Notes

### IdentityRegistryContract

- `RegisterDevice` now stores the May-2026 identity schema for new records:
  DID, public key, status, `registeredMacAddressHash`, `allowedIpCidr`,
  `metadataHash`, `didDocumentHash`, timestamps, and Fabric transaction
  identity.
- Raw MAC addresses are not written by the new registration path.
- Existing ledger records remain readable for compatibility and are not
  rewritten.
- Device lifecycle mutations are Fabric-admin-only.
- `RevokeDevice` writes a generic revocation audit event in the same Fabric
  transaction.

### AccessControlContract

- `VerifyAuthentication` performs blockchain-backed device lookup, ACTIVE
  status enforcement, ECDSA/SHA-256 signature verification, policy-based
  spoofing denial, and atomic authentication-event recording.
- `GetAccessPolicy` returns the global default policy when no ledger policy has
  been written.
- `UpdateAccessPolicy` is Fabric-admin-only and records a policy update audit
  event.

### AuditLogContract

- Provides the dedicated audit module required by the May-2026 SDS.
- Authentication events reuse the existing `AUTH_EVENT` and
  `AUTH_EVENT_BY_DEVICE` keyspace so prior audit history remains readable.
- New authentication events store `observedMacAddressHash` rather than raw
  observed MAC addresses.

## Tests Referenced

`npm test` in `blockchain/chaincode/identity-registry` currently runs:

- syntax checks for all contract/helper files;
- successful ECDSA authentication;
- modified-payload denial;
- wrong-key denial;
- suspended-device denial;
- unknown-device denial;
- MAC/IP spoofing denial classifications;
- incomplete-context allow/deny behavior;
- duplicate authentication event rejection;
- policy update as Fabric admin;
- policy update rejection for non-admin Fabric identity;
- policy-controlled MAC-mismatch allow behavior.

## Remaining Security Limitations

- The gateway still uses one configured peer endpoint; application-level peer
  failover remains a documented limitation.
- DID syntax validation remains stronger in the backend than in chaincode.
- The Fabric test-network endorsement policy was not redesigned.
- The prototype does not implement full W3C DID method registration,
  Verifiable Credentials, or MQTT transport.
