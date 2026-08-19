# Traditional Authentication Comparison

This directory contains the Phase 12/12B comparison harness for centralized
RADIUS and LDAP baselines.

The runner is intentionally conservative: it records actual measurements only
when the required local tools and isolated test services are available. It uses
repo-local runtime directories for generated service configs, databases, logs,
passwords, and shared secrets.

## Run

```bash
node comparison/run-comparison.js
```

Generated files are written to `comparison/results/` and are ignored by Git.
Generated service runtime files are written under:

- `comparison/radius/runtime/`
- `comparison/ldap/runtime/`

Those runtime directories are also ignored by Git.

Do not reuse administrator passwords, Fabric credentials, blockchain device
private keys, or institutional credentials for the baseline.

## Isolated Baselines

The default run creates:

- FreeRADIUS on `127.0.0.1:18120`
- OpenLDAP/slapd on `ldap://127.0.0.1:1389`
- synthetic identity `cbu-device-001`
- generated runtime-only passwords and RADIUS shared secret

The script stops the isolated FreeRADIUS and slapd processes after the
experiment.

## Scope

The Fabric reference is read from existing formal evaluation output under
`evaluation/results`. The comparison does not rerun or modify blockchain
results.

Fabric authentication timing covers the full implemented flow:

- challenge generation
- local ECDSA signing
- Fabric smart-contract verification
- immutable audit event commit
- MAC/IP network-context policy

RADIUS and LDAP baselines may measure narrower centralized credential
verification operations. The reports call out that scope difference explicitly.
