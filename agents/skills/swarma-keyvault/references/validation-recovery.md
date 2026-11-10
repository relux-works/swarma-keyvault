# Validation, updates and refusal recovery

## Source and installed state are separate

Use an exact reviewed checkout. Static inspection and confined public-fixture
verification do not establish live credentials, installed adoption, owner-presence
success or provider effects. Report actual execution separately from expected
behavior read from source.
Current `go.mod` declares Go 1.26.0 and toolchain go1.26.10. This is version
evidence, not an instruction to download/build. Native custody uses macOS cgo /
Security.framework and the paired Swift/CryptoKit Enclave helper.

Read actual selected source before proposing a command. Source locations:
`cmd/mac-keyvault/`, `cmd/mac-keyvault-kek/`, `cmd/swarma-keyvault/`,
`pkg/kekclient/`, `internal/grants/`, `internal/mugrant/`. Do not run a product
binary just to discover help in a static-only task. No install or profile
publishing is performed by adding this native skill.

Preserved compatibility locations are labels
`works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`, lock
`~/Library/Application Support/mac-infra/keyvault/init.lock`, device-bound blobs
`~/Library/Application Support/mac-infra/keyvault/enclave/`, and KEK audit
`~/Library/Application Support/mac-keyvault-kek/audit.jsonl`. These are documented
paths, not permission to read runtime homes. Updating source does not relocate
or migrate them. A rebuilt code identity can lose existing Keychain ACL access;
never repoint an installed binary or adjust ACLs as an agent recovery step.

## Choose evidence within authorization

For static work, check only diffs, frontmatter, links, actual dispatch/flag
registrations and code symbols. Read fixture sources to state expected positive
and refusal behavior; do not report them as executed tests. The public fixture pair in
[typed grants](grants.md#offline-verify-runnable-inert-public-example) has a confined
runner for tasks that authorize execution. Merely reading it is not a run result.

For separately authorized future qualification, select the lane explicitly:
fake-backed confined source tests, read-only native public-code qualification,
OWNER-SITTING custody/presence tests, and actual installed consumer/provider
acceptance prove different things. Existing repository wrapper
`scripts/keyvault-test-confined.sh` and the native certificate lane in
`docs/kek.md` govern their own prerequisites. The skip gate and native-input
allowlist do not by themselves prove confinement from native startup. Do not
unset a safety gate to rescue a failed run or call setup-unavailable a pass.
No build, Go test, fixture generator or runtime probe is prescribed here.

## Recovery and KEK code identity test lane

The default confined suite skips recovery and KEK code-identity fixtures. For
authorized macOS qualification, run the cgo fixture runner from the repository
root by itself. Keep logs in ignored `.temp/`.

```sh
CGO_ENABLED=1 go build -p 1 -o .temp/keyvault-codesigntest ./tools/codesigntest
MAC_KEYVAULT_SKIP_KEYCHAIN=1 KEYVAULT_CODESIGN_TESTS=1 .temp/keyvault-codesigntest run
```

The runner shares a private per-account lock across checkouts and retains one
tree under `~/.swarma-keyvault-codesign-tests/` with up to 24 executables from
the fixed fixture matrix. It verifies the default skips using the same test
binaries. The opt-in lane preserves the hardened recovery positive, no-runtime,
wrong-hash and debug-entitlement refusals, and the real KEK inspection cases.
The separately gated public certificate positive is documented in
`docs/kek.md`. These fixtures exercise public code and do not use installed
custody, owner presence or production signing.

The next opt-in run or `.temp/keyvault-codesigntest cleanup RUN_ID` removes the
exact eligible routine tree under the lock. It checks the recorded process group,
the ten-minute retention period and absence of `host-degraded` in the state
directory. A changed boot establishes process exit. Same-boot interrupted runs
without a finish record and other unknown state remain retained. Keep the lock
file. For a supervised operation select `run-observed`, then use
`.temp/keyvault-codesigntest cleanup-observed RUN_ID` only after the sysadmin
confirms assessment-service health and all owned children have exited.

## Refusal and uncertainty

On unavailable/denied presence, fingerprint mismatch, missing helper,
unreadable metadata, expiry or policy refusal: stop the attempt, retain sanitized
failure facts and send the precise decision back to the owner. Do not create,
rotate/delete, switch stores, automate prompts or weaken usages/extraction.
Enclave blobs are device-bound, not portable private-key backups.

On KEK unwrap/protocol/audit/authenticated-store failure: stop the service,
preserve envelope and encrypted store, and use the consumer's preapproved
recovery route. Never substitute a fresh KEK or empty store. Compare an audit
head with an independent retained checkpoint; local chain consistency alone
does not resist same-user wholesale rewrite.

On grant UNKNOWN, interruption, output failure after intent, corrupt/incomplete
journal or replay refusal: preserve exact state/epoch/config and request
correlation, do not resend, truncate, migrate or reset. An offline accepted
verification does not replenish an allowance or promise dispatch success.
Reprovisioning a new epoch needs a separate custodian decision about old holds,
revocations and replay, not automatic cleanup. Same-UID paths and checksums
supply neither isolation nor protected time.
