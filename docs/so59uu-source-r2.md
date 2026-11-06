# so59uu r2: bounded source components, workflow unavailable

This source tranche implements independently testable components of the accepted
design `3c7e28420d12efeabef1f1bf80d67956cbe5a8f28c39e1a335fe00e33244872f`,
based on commit `1564731cb6157ddca9fcf8a4dae3d4bde71287c6`. Design review371
accepted that exact design and its companion contracts. Subsequent source-only
production admission permits these components; it supplies no live deployment
admission, owner sitting, or adopted release.

`internal/reviewedsession` has no exported API. It is intentionally not registered
in the CLI or connected to any issuance, key manager, Enclave backend, publisher,
sampler, receiver, or transport. No command can produce a reviewed signature or
resume a snapshot through this package. `workflowAvailability` always refuses.
Existing commands retain their existing guarantees and behavior.

The source components provide:

- Closed input and commit/cancel/normalized-receipt parsing. Duplicate keys at any
  depth (including differently escaped spellings), unknown/missing fields,
  non-ASCII protocol strings, controls, invalid UTF-8/surrogates, non-integer
  numbers, noncanonical digests/base64url, unsupported profiles and out-of-range
  sequence integers refuse. Receipt parsing authenticates nothing.
- Four-byte big-endian bounded framing of complete buffers, with exact one-frame
  length checks and terminal short/error writes. A live inherited-FD reader,
  descriptor admission, cancellation, monotonic deadlines and extra-input
  detection during an actual session remain unimplemented.
- One common leading-eight-byte digest cue (`0001 0203 0405 0607`), solely for
  human comparison. It has about 2^32 generic chosen-pair collision work. All
  comparison components use the full 32 bytes, including the bytes outside this
  cue. No receipt digest can replace signing input.
- Russian profile/count/policy title components and a complete reason budget
  including `mac-keyvault: `, separators, digest delimiters and the actual fixed
  `alexis/grants-owner-v1 v1` key display. At that spelling the title allowance is
  119 scalars. Only optional informational title data can be fitted with an
  ellipsis. Empty/fallback/altered reason, digest, key or generation refuses in
  the pure final-reason comparison component. This component is **not installed
  at the backend dispatch boundary** and cannot confer reviewed guarantees on
  existing generic Describe callbacks.
- ASCII display admission, reversible quoted safe strings, and deterministic
  complete syntactic field/array-slot disclosure with a hard output cap. The
  tree is a renderer component, **not** the required per-profile semantic
  completeness validator, full Russian grant review or authority summary.
- Profile-specific raw Ed25519/P-256 SPKI fingerprint bytes, representation and
  last-eight-character tails; MU compressed P-256 IDs are reconstructed as
  canonical SPKI before hashing. Full independently supplied public bytes are
  compared. This proves neither pin provenance nor Matrix identity/E2EE.
- Owned byte-comparison data binding preimage, snapshot, review, session nonce,
  whole expected body/trailer, independently supplied expected receipt fields
  and current-send coordinates. It detects mutation of owned bytes and copies
  all ingress buffers. It validates no grant/admission/snapshot schema, issues no
  permit, and is **not a frozen typed plan or live session**. A successful
  comparison is not authenticated publication, owner approval or consent.

No public interface is added or substituted for the accepted proposed CLI/API.
The package-private types keep incomplete components out of production callers
until actual contracts can be composed and independently reviewed.

## Missing inputs and required next source decisions

Source-only admission resolves OI-02 only for this bounded source work. These
inputs remain absent and must not be filled from payloads, responses, local
configuration, host timezone data or guessed repository paths:

| Input | Required actual custody/contract decision |
| --- | --- |
| OI-03 | Sitting-script repository/path, immutable source/artifact binding, launcher and accountable credential boundary. The design's adapter name is an interface identifier only. |
| OI-04 | Authenticated original-event projection schema/source, fresh read and edit/redaction/plain-body semantics, error and idempotency contract. |
| OI-05 | Independently admitted exact sender/receiver/immutable room/type/kind, membership/posting permission and custodian pins. Synthetic `example.invalid` test values are not admissions. |
| OI-06 | Complete closed protected public admission/policy schema, provenance and actual owner/subject/registry/audience/resource/evidence constraints. No admission parser or invented defaults are provided. |
| OI-07 | Concrete executable/helper launch and custody interface; later exact candidate, rebuilt binary/helper and owner adoption tuple. |
| OI-08 | Independently admitted Europe/Moscow TZif bytes/hash/version/provenance and integration method. There is no host timezone lookup or fixed +03 substitute. |
| OI-09 | Immutable external codec/verifier source and qualification at the existing exact dependency pin. These components use only Go's standard library, acquire no dependencies and claim no codec qualification. |

Actual full-profile typed imports/projections, snapshot construction, semantic
coverage checks, pinned Moscow rendering, MU body/nonce/context composition,
authenticated script handoff, monotonic live session and one-use permit,
key-aware final/backend refusal, envelope assembly/verification and result
unknown-outcome handling still need implementation after their actual inputs are
admitted. No trust is gained from a self-asserted `event_state`, matching response
fields or copied artifact hashes. The separately supplied expectation in tests
demonstrates comparison only; it cannot simulate authenticated source custody.

The accepted four profiles remain repository, local repository, A2A certificate
and Mac MU grant. MU attestation issuance, Linux/Keymaker sessions, generic
signing, root revocation, provider effects and publisher execution are deferred.
The d202 choices remain Russian review/title, full subject MXID and accurate
fingerprint tail in a future complete review, Moscow instants, identical short
cue in post/prompt, and adoption only at an owner sitting.

## Validation scope

The package has focused standard-library-only tests for strict protocol parsing,
framing and failure writes, whole-body/full-digest/context comparisons, defensive
ownership, safe disclosure, title budgets and fingerprint representation. It
also has two bounded parser fuzz targets. Run the package with an offline
confinement runner, private HOME/TMP/cache and read-only source/tools:

```
go test -count=1 -cover ./internal/reviewedsession
go vet ./internal/reviewedsession
go test -run=^$ -fuzz=FuzzControlParser -fuzztime=5s -parallel=2 ./internal/reviewedsession
go test -run=^$ -fuzz=FuzzInputParser -fuzztime=5s -parallel=2 ./internal/reviewedsession
```

The accepted 107 negative/12 positive **end-to-end** matrix is not satisfied by
these component tests. There is no fake signing-dispatch positive neighbor and no
private operation in these tests. A live protocol, full renderer, independent
exact-head review, marker/check gates, signed PR landing and separately authorized
Mac rebuild/native visibility/presence/cancel/adoption remain later gates. Source
tests establish neither native qualification nor activation readiness.
