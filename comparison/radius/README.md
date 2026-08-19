# RADIUS Baseline Notes

Phase 12B creates an isolated FreeRADIUS baseline using synthetic credentials,
for example:

- username: `cbu-device-001`
- password: generated synthetic test password
- shared secret: generated synthetic test secret

No RADIUS password or shared secret should be committed to Git. The runner
generates them under `comparison/radius/runtime/`, which is ignored.

Minimum tools needed:

- `freeradius` or `radiusd`
- `radtest`
- `radclient`

The current harness measures Access-Accept, Access-Reject, static credential
reuse, sequential latency, concurrency, outage/recovery, identity disable, and
Calling-Station-Id behavior. MAC/IP enforcement must be reported as
`NOT_CONFIGURED` or `NOT_NATIVE_TO_BASELINE` unless the local FreeRADIUS policy
explicitly evaluates those attributes.
