# LDAP Baseline Notes

Phase 12B creates an isolated OpenLDAP baseline using synthetic credentials.

Example identity:

- suffix/base DN: `dc=cbu-auth-test,dc=local`
- bind DN: `uid=cbu-device-001,ou=devices,dc=cbu-auth-test,dc=local`
- password: generated synthetic test password

No LDAP password should be committed to Git. The runner generates credentials
under `comparison/ldap/runtime/`, which is ignored.

Minimum tools needed:

- `slapd`
- `ldapwhoami`
- `ldapsearch`
- `ldapadd`

LDAP simple bind validates centralized credentials. MAC/IP spoofing checks are
not native to this baseline unless a custom surrounding policy is explicitly
configured and documented.
