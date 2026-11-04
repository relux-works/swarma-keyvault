# swarma-keyvault

macOS key custody and narrow signing/KEK interfaces, extracted from the published
`relux-works/mac-infra` component at `3e9ee3e749f3ef8b6f6d4f188c39bb8207efa337`.
The current source candidate retains P-256 key custody, the paired Secure Enclave
helper, signer contract 1, the SSH agent bridge and the `kek-1` broker/client.
Standalone validation and installed adoption are pending.

The module is `github.com/relux-works/swarma-keyvault`. The public KEK client is
`pkg/kekclient`; the signer client remains internal in this initial extraction.
Existing consumers retain their qualified dependency until they adopt a release.
Old and new module imports have distinct Go type and sentinel identities; compare
errors against the sentinel from the client module that produced the error.
Existing labels, generations, schema, Keychain/Enclave locations and live binaries
keep their current compatibility contract. Source extraction performs no store
migration or installed binary replacement.

## Tools and local build

The initial custody target is macOS with Go 1.25.5 or later, cgo and the Apple
Command Line Tools. `go` builds the two CLI programs, `swiftc` builds the paired
CryptoKit helper, and macOS `sandbox-exec` confines fake-backed test processes.
From this directory, build only new local artifacts:

```sh
mkdir -p .temp/build
CGO_ENABLED=1 go build -trimpath -o .temp/build/mac-keyvault ./cmd/mac-keyvault
CGO_ENABLED=1 go build -trimpath -o .temp/build/mac-keyvault-kek ./cmd/mac-keyvault-kek
swiftc -O -o .temp/build/mac-keyvault-enclave cmd/mac-keyvault-enclave/main.swift
```

Keep the helper beside its matching CLI. These commands do not install, sign or
replace existing binaries. Operating an installed broker additionally requires its
qualified code identity and provisioning contract. Rebuilding a binary trusted by
existing Keychain ACLs needs its own planned adoption; do not repoint existing
installed paths at these artifacts.

Run the fake-backed suite through its inherited confinement wrapper:

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 scripts/keyvault-test-confined.sh ./... -count=1
```

The wrapper applies confinement before native startup. Real Keychain, owner
presence and installed-service tests are separate attended operations. Confined
public-certificate tests can prove a trust refusal, not a native positive match.
Required native certificate qualification and its limits are described in
[the KEK contract](docs/kek.md). Test/build logs and scratch belong under `.temp/`.
The native-input allowlist is a review tripwire; it does not replace confinement.

Read [the KEK contract](docs/kek.md) and [SSH/new-key onboarding](docs/keyvault-ssh-new-keys.md)
before selecting an interface. Generic signing is not typed grant or release
authority. Same-user sockets and code binding do not prove per-agent identity.

## Certificate work

Owner direction, 2026-10-31: certificates and grants always remain stored locally,
with an agent-facing API and configurable provider synchronization. A certificate
may hold multiple grants; finite validity is capped at ten calendar years and
reissue or expansion requires a fresh owner signature. This certificate layer,
its audit coverage and Matrix requester/effect integration are not implemented by
the compatibility extraction above.

The portable `internal/grants` package provides bounded canonical decoding,
typed untrusted projections, P-256 certificate signature verification against an
explicit public owner/SPKI pin and comparison of declared certificate/request
fields. Matching includes exact subject,
audience, cycle/use, repository and half-open validity predicates. These helpers
do not establish issuer trust, authenticate receiver context or DELETE receipts,
check current revocation, reserve a use or authorize an effect. Run their isolated
portable tests without native custody access:

```sh
CGO_ENABLED=0 go test ./internal/grants
```

The composed signed-request check matches against exactly the payload returned
by public signature verification under the supplied pin. DELETE matching
explicitly requires its paired CREATE entry and same-cycle use. It still does
not authenticate the CREATE result or authorize dispatch.

Logical uses retain the exact `(certificate_id, entry_id, operation_use_id)`
namespace as separate comparable fields. Use IDs may repeat across entries;
the signed cycle is checked separately and does not add another allowance.
Request IDs identify correlation, not new uses. Deriving this representation
key neither reserves a use nor authenticates any request or current state.

Public revocation checks additionally require the retained certificate's exact
signing authority and target ID, using one explicit pin for both signatures.
Future-effective scheduling refuses with a distinct internal reason; malformed
representations retain their schema/encoding refusals. This introduces no new
external wire error code.
Immutable replay comparisons require the exact signed envelope and payload in
the same typed ID namespace. A second valid signature under the same ID is a
collision. These read-only checks do not insert or revoke records, authenticate
current storage/lifecycle state, refresh validity or reserve/release a use.

Internal journal framing can encode and read bounded binary records with explicit
sequence, predecessor-digest and epoch-reference comparisons. Its versioned
allocation limits are provisional record-layout bounds. Bodies remain opaque;
framing neither validates lifecycle records nor authenticates an epoch, receiver
or provider. It does not append, sync, repair or truncate a journal. Package tests
include exact-byte fixtures, malformed/truncated records and checksum controls;
these checks establish no native durability or installed custody qualification.

The internal offline scanner checks a physical frame chain from genesis through
EOF under an explicit byte budget of at most 64 MiB. It returns only a complete
physical summary; corruption, an incomplete tail or an over-budget stream returns
no summary. It neither reconstructs typed grant state nor authenticates the
caller-supplied epoch reference, and it never repairs or truncates a journal.

The internal activation-body codec checks the bounded binary layout, complete
canonical certificate representation, reference counts/order and explicit
sequence/audit references. It preserves the exact envelope. Signature validation,
history/ID resolution, the complete RESERVED set, current authority and atomic
state/audit changes require separate checks; this codec performs no activation.
