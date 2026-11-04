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
An empty stream is accepted as a zero-frame summary. Without a separate trusted
rollback witness, that result cannot distinguish an empty journal from one
truncated to zero bytes.

The internal activation-body codec checks the bounded binary layout, complete
canonical certificate representation, reference counts/order and explicit
sequence/audit references. It preserves the exact envelope. Signature validation,
history/ID resolution, the complete RESERVED set, current authority and atomic
state/audit changes require separate checks; this codec performs no activation.

### Prepare an unsigned repository certificate

Build the portable authoring CLI without native custody access:

```sh
CGO_ENABLED=0 go build -o .temp/build/swarma-keyvault ./cmd/swarma-keyvault
CGO_ENABLED=0 go test ./internal/grants ./cmd/swarma-keyvault
```

`grants prepare` takes an explicit canonical JSON draft, an owner Matrix account
and a separate public P-256 SPKI DER file. It creates a first-issue certificate
with a private repository CREATE and its paired DELETE, one finite use of each
per explicitly listed cycle. It supplies no default target, time or cycle.
The draft has exactly these eight fields (shown formatted for reading):

```json
{
  "audience": {"deployment_id": "example", "executor_id": "example"},
  "certificate_id": "example",
  "cycles": [{"channel": "encrypted-dm", "cycle_id": "codex-dm", "runtime": "codex"}],
  "expires_at": "2026-11-04T03:00:00Z",
  "name": "example-private-repository",
  "not_before": "2026-11-04T02:00:00Z",
  "organization": "example",
  "subject": {
    "account_mxid": "@requester:example.invalid",
    "device_ed25519": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    "device_id": "EXAMPLE"
  }
}
```

Replace every example value with the intended explicit value. The input file
must use the existing canonical ASCII JSON representation: sorted object keys,
no whitespace, no duplicate keys and no trailing newline. Existing certificate
representation and validity limits apply. Drafts are limited to 65,536 bytes;
public DER input is limited to 1,024 bytes. No private key belongs in either file.

```sh
.temp/build/swarma-keyvault grants prepare \
  --plan .temp/draft.canonical.json \
  --owner-mxid @owner:example.invalid \
  --issuer-spki-der .temp/owner-public.der \
  > .temp/certificate.unsigned.json 2> .temp/certificate.review.txt
```

`--plan -` reads the bounded draft from stdin. Stdout contains the exact unsigned
canonical payload without a newline. Stderr contains an explicitly unsigned
full-field review and SHA-256 of `swarma-grants/certificate/1`, LF and those exact
payload bytes. The issuer key ID is SHA-256 of the exact supplied public DER.
The CLI itself writes no files; the shell redirections above create the outputs.
Input refusal produces no payload. A failed or short review write prevents
payload output; a failed or short payload write returns failure, so discard any
partial redirected output on nonzero exit.

This command does not enroll the supplied owner or key, authenticate a declared
subject/channel, sign, access Keychain, reserve a use or contact a provider.
Declaring an encrypted channel does not demonstrate a qualified receiver.
Typed issuance must separately validate and display the same exact payload
under its owner-presence contract. A prepared document grants no active rights.

### Issue the selected private repository certificate

`grants issue --payload FILE|- --owner-spki-der FILE` signs the complete canonical
payload using the existing `alexis/grants-owner-v1` key, explicit generation 1.
This initial interface accepts only owner `@alexis:gr.relux.works`, one cycle,
one private CREATE for `relux-works/matrix-grants-poc-261031` and its paired
single-use DELETE, with no superseded certificates. DELETE is signed scope;
this interface executes no repository operation.

The separate public DER file must be obtained through the intended enrollment
contract. Supplying it does not enroll an owner or make a certificate trusted by
a consumer. Before the private call, the actual resolved key must match that
exact public DER, semantic address and generation, Secure Enclave store,
user-presence requirement and non-extraction policy. No generic digest or key
selector is exposed. Complete payload validation precedes store access.

Build a separate native CLI with cgo and keep the matching Swift helper beside
it; preserve installed binaries and existing ACL trust:

```sh
CGO_ENABLED=1 go build -trimpath -o .temp/build/swarma-keyvault ./cmd/swarma-keyvault
swiftc -O -o .temp/build/mac-keyvault-enclave cmd/mac-keyvault-enclave/main.swift
```

This command requires an independently accepted build, the separately provisioned
owner-presence key and an attended operation. Before invoking it, explain the
expected OS action/digest prompt; the human alone answers that prompt. A denied
or unavailable prompt ends the attempt. The command never creates a key, retries
signing or falls back to another store. Fake-backed tests do not qualify native
presence, helper execution or Keychain ACL behavior.

Stderr displays a short Russian scope statement, the local unverified Matrix
subject association, all signed fields and the domain-bound digest. A failed or
short review write prevents the private call. Stdout receives only the existing
signed-certificate envelope, without a newline, after its signature verifies
against the exact payload and public pin. On any nonzero exit, discard redirected
output, including a possible partial output after a successful signature. Issuing
does not activate, persist or reserve a certificate, authenticate a requester,
or contact a provider.
