# KEK broker boundaries: contract kek-1

Source: `cmd/mac-keyvault-kek/main.go`, `internal/keyvault/kek/server.go`,
`internal/keyvault/kek/audit.go`, `pkg/kekclient/` and `docs/kek.md`.
There is no `mac-keyvault kek` verb: the separate `mac-keyvault-kek` broker
uses ordinary non-extractable login-Keychain P-256 records with `decrypt` usage.
Its code identity/ACL is distinct from the CLI and the Enclave signing helper.

## OWNER-SITTING / admitted-service catalogue

| Broker operation | Actual syntax boundary; never an agent step |
| --- | --- |
| `create` | `--address S/P`, optional `--title`, `--not-after RFC3339`; creates generation 1 |
| `pub` | `--address S/P`, optional `--version N`; public output still reads Keychain |
| `unwrap` | `--address S/P --socket PATH`; one request; client launches it inside service boundary |
| `rebind` | Same address/socket flags; one rebind request |
| `audit-verify` | No arguments; checks local chain and reports entry count/head |

Creation, public lookup and service commands disable Keychain UI before vault
access; UI denial is a failure, not permission to repair ACLs. `audit-verify`
reads the audit, not a custody key. Broker exit 2 is usage and 1 failure;
do not apply mac-keyvault's exit-3 convention to it.

## Protocol and admission

Envelope format is `mac-keyvault-kek-envelope`, version 1; wire contract is
`kek-1`. Public header names address, generation, SPKI fingerprint, KCV and
ECIES ciphertext. The sealed payload repeats the header and contains the code
requirement, install path and KEK. Strict parsing rejects unknown/missing/null
or duplicate contract members, wrong types and trailing data. Header/payload
and KCV mismatches refuse.

Before releasing a KEK the broker checks peer code through its socket audit
token, hardened runtime/library validation and absence of get-task-allow;
checks contract/request/address; applies record readability, decrypt usage and
expiry; decrypts and compares headers/fingerprint; reinspects peer code and its
exact sealed binding; then appends and syncs the audit before answering.
Audit failure prevents a successful secret response. Reinspection is not an
atomic defense against an exec after the last observation.

CDHash binding is canonical `cdhash H"<40 lowercase hex>"`. Certificate binding
is `certificate leaf = H"<40 lowercase hex>" and identifier "<identifier>"`.
Use package constructors rather than accepting arbitrary requirement clauses.
Rebind supports CDHash only and returns no KEK. An ad-hoc-signed caller cannot
satisfy a leaf-certificate binding. Native validation disables online
revocation/notarization access but synchronous native calls do not promise
hard cancellation or measured absence of network traffic.

The closed broker error codes are `bad_request`, `caller_refused`,
`envelope_invalid`, `not_found`, `expired`, `usage_refused`, `metadata_unknown`,
`rebind_refused`, `unsupported_primitive`, `security`. Unknown codes or malformed
responses are `ErrProtocol` in the client. Withhold raw secret-bearing output
and broker stderr from diagnostics.

## Limits that change recovery

Code binding does not attest repository review, release approval, an individual
agent or a separate OS user. The client checks KCV, but its service must check
the authenticated store. Audit chain consistency does not detect a same-user
rewrite of the entire log; compare against an independently retained head.
Deleted/reset Keychain custody can make the envelope permanently unusable;
this interface cannot export the private key. Preserve the existing qualified
binary and approved recovery plan. See [integration](kek-integration.md) and
[validation/recovery](validation-recovery.md).
