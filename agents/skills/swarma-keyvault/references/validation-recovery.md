# Validation, updates and recovery

## Source and installed state

Obtain a separate checkout of the exact reviewed source revision for build/test
commands in this skill. An exported skill folder alone is not a Go checkout.
The repository is `relux-works/swarma-keyvault`, module
`github.com/relux-works/swarma-keyvault`. Initial custody targets macOS; use Go
1.25.5 or later, cgo and the Apple Command Line Tools. Build only local artifacts:

```sh
mkdir -p .temp/build
CGO_ENABLED=1 go build -trimpath -o .temp/build/mac-keyvault ./cmd/mac-keyvault
CGO_ENABLED=1 go build -trimpath -o .temp/build/mac-keyvault-kek ./cmd/mac-keyvault-kek
swiftc -O -o .temp/build/mac-keyvault-enclave cmd/mac-keyvault-enclave/main.swift
```

Keep the helper beside its matching CLI. These commands do not install or sign
the output. This module supplies no replacement installer. Use the deployment's
qualified install/update procedure, preserve exact current binaries/configuration
and rollback evidence, and coordinate actual consumers before changing links,
services or code identity. Never copy local builds over a live trusted binary.

Existing compatibility locations remain:

- labels: `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`;
- lock: `~/Library/Application Support/mac-infra/keyvault/init.lock`;
- device-bound Enclave blobs: `~/Library/Application Support/mac-infra/keyvault/enclave/`;
- KEK broker audit: `~/Library/Application Support/mac-keyvault-kek/audit.jsonl`.

The repository name does not relocate these paths. A key created by one binary
may refuse another code identity through its Keychain ACL. Broker UI is disabled;
a refusal can therefore be silent. Reauthorization needs the existing qualified
owner-attended procedure, not automatic ACL edits. An instruction package install
does not install the CLI, re-register keys, repin consumers or start a service.

## Match evidence to the contract

Run from the source checkout and retain logs under `.temp/`:

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 scripts/keyvault-test-confined.sh ./... -count=1
```

The wrapper confines the process tree from exec, including native startup; the
native-input allowlist is a review tripwire, not enforcement. The skip gate keeps
real login-Keychain/Enclave integration tests out of this lane. Fake-backed tests
exercise valid operations and meaningful refusals. Skipped private tests do not
qualify hardware presence, ACL approval or an installed consumer.

For changes to a specific contract, retain its nearby valid controls and
rejections: strict schema/duplicate decoding, operation usage/expiry, generation
binding, invalid signatures, KEK caller/payload/audit/store checks, or SSH
namespace/socket/confirmation refusals. Check observable effects, not merely a
nonzero exit. Signer golden fixtures and client tests are under
`internal/keyvault/`; public-client tests are under `pkg/kekclient/`.

Certificate-mode acceptance additionally requires the ordered read-only native
canary and public-code lane in [the KEK contract's Tests section](kek.md#tests).
Run the public-code lane only after the canary establishes its intended
confinement. A canary build failure leaves its dependent lane unstarted; it is
not a native pass. Confined public-certificate tests exercise trust refusal,
whereas the separate lane must establish actual certificate/identifier matches
and both mismatches. Review pre-Go-init native inputs for that lane.

Real Keychain/Enclave tests create/delete test-namespace items and may require
owner interaction; run them only in the admitted attended environment. Never
unset the gate to rescue an ordinary confined run. Report each selected lane's
actual verdict, including setup-unavailable and skipped states, and run all
independent selected lanes even when one fails. A safety-dependent lane remains
unstarted if its prerequisite fails.

Installed adoption also requires the actual binary identity, retained key
generation/fingerprint, both sides of the service pair, applicable positive and
refusal controls, audit head and rollback check. Source tests do not establish
those facts. For SSH interoperability and its limits, use the
[new-key guide](keyvault-ssh-new-keys.md#developer-verification).

## Recover without changing authority

On a refused/unavailable prompt, stop the attempt and report the controlled
failure. Do not automate confirmation, retry unattended, switch stores or
change policy. On invalid metadata, missing helper or a mismatched fingerprint,
preserve the record and exact revision while diagnosing the cause; deletion or
recreation requires its own actual authorization.

On KEK unwrap, protocol, audit or authenticated-store failure, stop the service.
Never generate a new KEK or initialize an empty store as fallback. Retain the
envelope, encrypted store, qualified binary/configuration and sanitized failure
facts for the consumer's recovery procedure. The same user can rewrite the
broker/envelope or the whole audit log, so an internally consistent chain alone
is insufficient: compare its head with an independently retained checkpoint.

Keychain reset/deletion can make an envelope permanently unusable. Enclave blobs
are device-bound and copying them does not provide portable key recovery.
Use an already designed recovery envelope or the service's authorized rebuild
procedure; do not promise private-key export. Preserve old verification trust
through rotation. For a stale SSH socket, establish that its owning process is
gone before removing only that socket; never remove a live socket or restart
another user's service as a diagnostic shortcut.
