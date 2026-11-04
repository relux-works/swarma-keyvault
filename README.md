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
Command Line Tools. `go` builds the custody, KEK and grant CLI programs, `swiftc` builds the paired
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

### Local repository request and mediation

The bounded local path accepts only the first-issue private CREATE for
`relux-works/matrix-grants-poc-261031`, under `@alexis:gr.relux.works` and one
explicitly enrolled cycle. The paired DELETE remains signed certificate data;
this executor never dispatches it. This is a local proof of concept, with no
Matrix receiver, device authentication, revocation/reissue workflow or protected
clock. Its subject is a custodian-declared association to a separately pinned
P-256 requester key; copying subject JSON without that key cannot authenticate
a request. The subject has exactly `account_mxid` and `device_id`; it contains
no Matrix Ed25519 key. `encrypted-dm` is a declared cycle label: this local path
does not authenticate a Matrix device, encrypt a message or deliver via Matrix.

Use the explicit local authoring and issuance commands with independently
obtained owner and requester P-256 SPKI DER files:

```sh
.temp/build/swarma-keyvault grants local-prepare \
  --plan local-plan.json --owner-mxid @alexis:gr.relux.works \
  --issuer-spki-der owner.spki.der --requester-spki-der requester.spki.der \
  > local-certificate.json
.temp/build/swarma-keyvault grants local-issue \
  --payload local-certificate.json --owner-spki-der owner.spki.der \
  --requester-spki-der requester.spki.der > signed-local-certificate.json
```

The bounded canonical draft has the same eight authoring fields shown above,
with the two-field local subject. `local-prepare` makes no private call. It
derives `requester_spki_sha256` as the full lowercase SHA-256 of the exact
separate requester DER and emits `grants-local-certificate-1`. `local-issue`
checks that signed constraint against the independently expected requester DER
before accessing the owner key. The hash never selects a trusted key. Its
complete Russian review includes the declared subject, full requester hash,
all signed fields and an explicit statement that no Matrix device is
authenticated and nothing is encrypted or delivered through Matrix. The
presence prompt names `grant local repository.create`, the target and digest.
The owner key, presence, review-write and single-attempt requirements of
`grants issue` also apply here.

The resulting envelope is `grants-signed-local-certificate-1`; its signature
covers SHA-256 of `swarma-grants/local-certificate/1`, LF and the exact canonical
payload. Certificate and envelope limits are 65,536 and 98,304 bytes. The existing
Matrix `grants prepare` and `grants issue` formats remain separate and retain
their original contracts.

An already provisioned `swarma-grants/requester-local-v1`, generation 1, must be
an Enclave non-presence, non-extractable signing key. Request signing checks the
actual resolved record and separate public pin before its single private call:

```sh
.temp/build/swarma-keyvault grants request \
  --payload request.json --requester-spki-der requester.spki.der > local-request.json
```

`request.json` is the complete canonical `grants-local-operation-1` payload
(at most 8,192 bytes), including explicit certificate/entry/cycle/use IDs, subject,
audience, CREATE target and expiry, with the same two-field local subject.
This command verifies its own resulting
signature but does not enroll a key or prove that a certificate allows it. The
new canonical envelope has exactly `payload`, `signature`, `type`, with type
`grants-local-request-2`. Payload and low-S DER signature use strict unpadded
base64url; signing covers SHA-256 of `swarma-grants/local-request/2`, LF and the
exact request bytes. Limits are 12,288 bytes overall, 10,923 encoded/8,192 decoded
payload bytes and 96 encoded/72 decoded signature bytes. The local correlation
is SHA-256 of `swarma-grants/local-operation/1`, LF and the exact operation bytes;
it is distinct from the signature digest and the existing Matrix correlation.

The custodian supplies a separate canonical local configuration, at most 8,192
bytes, as an owner-private regular 0600 file, without a final-component symlink.
It has exactly these fields (formatted here for reading; replace all placeholders):

```json
{
  "audience": {"deployment_id": "explicit-local-deployment", "executor_id": "explicit-local-executor"},
  "cycle": {"channel": "encrypted-dm", "cycle_id": "codex-dm", "runtime": "codex"},
  "gh_path": "/absolute/path/to/gh",
  "name": "matrix-grants-poc-261031",
  "organization": "relux-works",
  "owner_mxid": "@alexis:gr.relux.works",
  "owner_spki": "UNPADDED_BASE64URL_OF_SEPARATELY_VERIFIED_OWNER_SPKI_DER",
  "requester_spki": "UNPADDED_BASE64URL_OF_SEPARATELY_VERIFIED_DISTINCT_REQUESTER_SPKI_DER",
  "state_dir": "/absolute/path/to/private-local-state",
  "subject": {
    "account_mxid": "@actual-requester:example.invalid",
    "device_id": "DECLARED_DEVICE"
  },
  "type": "grants-local-enrollment-2"
}
```

Both public pins must be valid distinct P-256 SPKI DER keys. A P-256 requester
pin is not a Matrix Ed25519 device key. All subject, audience and cycle values
must match the signed certificate and request exactly. Provision the state
directory explicitly with owner-only 0700 permissions before execution; no
request field or CLI flag can override the enrollment, pins or provider path.
Keep the same exact config and state directory for subsequent calls. Changing
config bytes changes the journal epoch, SHA-256 of `swarma-grants/local-state/2`,
LF and exact config bytes, and refuses existing history. Old local enrollment,
attestation and journal formats are rejected without automatic migration,
truncation or reset.

```sh
.temp/build/swarma-keyvault grants execute \
  --config enrollment.json --certificate signed-local-certificate.json \
  --request local-request.json
```

The mediator validates both signatures, exact fields and host-time validity
before reservation. It checks the configured provider path with `Lstat` before
opening state and again under the lock immediately before reservation: it must
be a regular file with an execute bit, and a final-component symlink refuses.
A failed check returns a plain refusal without consuming a use or calling the
provider; the first check opens no state. Lock acquisition can create the lock
and empty journal infrastructure, but a repeated-check refusal appends nothing.
These metadata checks do not prove binary format, ACL eligibility or prevent a
same-user replacement race. A start failure after intent remains UNKNOWN/held.
Under one local file lock it replays the complete bounded
journal, then writes and syncs a reservation containing the exact certificate,
request and use/correlation identity, followed by a synced dispatch intent.
Only then does the selected absolute `gh` executable receive one
`api --hostname github.com -X POST orgs/relux-works/repos --input -` invocation,
with structured JSON stdin for the exact private repository. It uses existing
GitHub CLI authentication; it never reads or exports credentials. No shell,
existence probe, adoption, automatic retry or DELETE is performed. The process
has a 30-second deadline and bounded stdout/stderr. A successful receipt must
contain a positive integer repository ID, nonempty node ID, exact full name
and `private: true`, and must be durably recorded before reporting success.

The CLI emits a local `succeeded` observation with repository identifiers, or
`unknown` and a nonzero exit when dispatch/receipt durability is uncertain.
After a reservation, the use stays held; a new request ID does not replenish it.
Do not resend or manually erase state after an unknown result, failed output,
interruption or incomplete/corrupt journal. Replay never truncates or repairs
history automatically. Local state is limited to 256 held uses and 64 MiB.

Host time, file sync and cooperating same-user callers are the boundary. A
same-UID process can rewrite config/state or call `gh` directly; this path claims
no rollback resistance, protected time or exclusive provider credential access.
Fake keys, storage fault injection and Go subprocess fixtures exercise this path
under confinement; they do not qualify real owner presence or provider effects.
Discard partial signing output on any nonzero exit. Execution output failure
may follow an actual effect: preserve the journal and treat the use as held.

## Application-key grant preparation

The separate `grants-a2a-certificate-1` profile binds a full Matrix account ID
and a P-256 public-key SPKI SHA256. Its current narrow scope is one private
CREATE of `relux-works/matrix-grants-g2-261104`, one use, a positive interval of
at most 30 minutes, and no DELETE. It does not reinterpret an existing local
certificate, authenticate a Matrix device or implement E2EE. Application-key
signatures do not isolate processes sharing the same OS user or provider login.

Prepare the exact unsigned certificate with separately admitted public pins:

```sh
.temp/build/swarma-keyvault grants a2a-prepare \
  --payload certificate.canonical.json \
  --owner-spki-der owner.der --requester-spki-der grantee.der \
  > certificate.checked.json 2> certificate.review.txt
```

This public-only operation returns the unchanged checked payload and a complete
review. The presence reason derives from that same immutable payload: action,
private resource, full grantee ID, 16 hexadecimal characters of its key hash,
the exact interval in MSK, and the final 12 hexadecimal characters of the
domain digest. Seconds and the second date are included when needed; times are
not rounded. An invalid, control-containing or over-200-Unicode-scalar reason
refuses preparation. Nothing is truncated. This cap matches the current helper
preprocessing; it is not evidence that macOS displays every character.

The distinct `a2a-issue` command takes the same flags. It prepares the complete
certificate and reason before constructing the signing manager, then requires
the fixed owner key's exact generation, public pin, nonextractability and
Enclave/presence policy. It writes the full review before the private call and
verifies the resulting DER low-S signature. It neither creates keys nor installs
or activates a grant. A separate attended authorization is required to invoke
it; the human handles the OS prompt. A failure produces no retry or fallback.

For a requester, public preparation and signature packing are separate:

```sh
.temp/build/swarma-keyvault grants a2a-request-prepare \
  --payload request.canonical.json --request action.canonical.json \
  > request.prepared.json

.temp/build/swarma-keyvault grants a2a-request-pack \
  --payload request.canonical.json --request action.canonical.json \
  --signature request.signature.der --public-spki-der grantee.der \
  > request.envelope.json
```

Preparation emits exact base64url payloads and `digest_sha256`: SHA256 of
`swarma-grants/a2a-request/1`, one LF, and the exact canonical request. The
admitted `mac-keyvault sign --digest HEX --format ecdsa-der-low-s --out FILE`
primitive signs those 32 digest bytes once. Hashing the digest file again or
signing the request without its domain is a different operation. Packing checks
the signature against the supplied public key; that check alone does not make
the key trusted by a receiver. Scratch inputs and outputs belong under `.temp/`.

The request has twelve closed string fields in byte-sorted order: `action`,
`audience`, `expires_at`, `grant_registry_sha256`, `issued_at`, `nonce`,
`request_sha256`, `resource`, `room_id`, `sender_mxid`, `topic`, `version`.
It carries no grant. Requests last at most five minutes; nonces and hashes are
64 lowercase hexadecimal characters. The separate action payload is exactly
`name`, `organization`, `visibility`. All signed JSON uses the restricted
printable-ASCII canonical grammar: no whitespace, trailing LF, duplicate or
unknown members, Unicode escapes or repair. Wire keys are exactly `payload`,
`request`, `signature`, `type`; binary fields use unpadded canonical base64url.

The internal public verifier consumes separately pinned key and grant registries,
looks up the full actual sender, verifies owner and request signatures, exact
audience/context/payload hashes and validity, and selects exactly one applicable
nonrevoked grant. A short display alias cannot substitute for a full sender ID.
The event context must come from an admitted authentic projection; caller-supplied
JSON is not itself evidence of network origin. Verification does not reserve a
nonce/use, authorize provider dispatch or implement a live Matrix intake.
Authentic event projection integration and actual presence/provider
qualification for this new profile remain separate work.

The internal read-only `ParseA2AObservation` adapter accepts the closed
`a2a.event-verification-input/1` observation profile. It checks full sender,
selected stored-session receiver, exact requested/returned event IDs, room
presence and the independently configured room, topic root and slug. An absent
returned room is explicitly weaker endpoint-only context, never a returned-room
match. Its caller must establish a successful invocation of an admitted
projection binary; a JSON file alone cannot establish that provenance.

The adapter decodes strict bounded JSON without duplicate keys or Unicode
replacement, then requires the exact five-field `m.text` request wrapper,
configured human labels, one full receiver mention and matching thread/reply
relations. Both explicit reply and no-re fallback forms have contract tests.
It reconstructs the expected human prefix and extracts the remaining bytes once;
it never trims, repairs CRLF, scans markdown fences or chooses another envelope.
Extraction alone does not authenticate a request: the inert bad-signature
fixture extracts but fails the public verifier. Executed conformance with an
actual upstream formatter and a qualified live projection remains pending.

The internal G2 mediator rechecks the original event before opening state,
under its lock, and immediately before one fixed private repository CREATE.
It uses a separate explicitly initialized state directory/epoch; execution opens
existing files only. Initialization refuses occupied directories, and execution
refuses missing, empty, corrupt, partial, linked or incorrectly permissioned
state. It never initializes or repairs a replacement journal during execution.
This profile does not open or migrate the earlier local-profile journal.

Grant-use and request-nonce indexes are separate and independent of registry
digests. Refreshing a registry cannot restore a consumed grant, and a new grant
cannot replay an old nonce. The local journal holds the allowance through
durable reservation, dispatch intent and validated receipt under one lock.
Ambiguous process/receipt/outcome failures retain the use with `unknown`; there
is no automatic retry, release, cleanup or DELETE. File checks, checksums and
cooperating-process locks do not resist same-UID rollback or bypass. These APIs
have isolated fake/process-fixture qualification; public CLI configuration,
admitted live projection and actual operational acceptance remain pending.
