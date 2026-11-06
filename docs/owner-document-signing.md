# Exact owner document: preparation available, native signing unavailable

This is the new source-only OWNER-SITTING lane. It does not draft a delegation,
select Ivan's key, change grant text, retry KV68/367, or compose pending PR70.
It is based on actual main `16e0fe6d0898b8cb0e8f9ce236dd9cef87e14ff0`.

## Source-bound contract and the precise blocker

The existing generic file-signing contract is in
`cmd/mac-keyvault/main.go` (`digestFlags.resolveData`, `runSign`, `runVerify`):
SHA-256 of the **exact file bytes**, P-256 ECDSA, detached strict low-S DER.
`internal/keyvault/ecdsa.go` parses and verifies that representation.
`internal/keyvault/keyvault.go: SignIfKey` supplies a final gate on the actual
resolved key and checks the resulting signature. We reuse these algorithms;
there is no new envelope, domain prefix, canonical JSON, grant codec or receipt
format. A document signature does not become `grant/1` or enroll any authority.

The existing typed owner address is `alexis/grants-owner-v1`, generation **1**,
Secure Enclave, user presence required, extraction `none`. The separately supplied
exact P-256 SPKI DER must match the actual resolved key before any private call,
as in `internal/grantissuer/repository.go` and `cmd/swarma-keyvault/mu_issue.go`.
Supplying a public key file proves no registry provenance or owner identity.

Decision 154's source rule (`internal/mugrant/issuer.go: checkReason`) refuses
an over-200-scalar/control/format reason rather than truncating it. The candidate
brief reason, **including** `mac-keyvault: ` and the actual key suffix, is below
that cap and is tested against the full digest. It accompanies full review; it
cannot replace full review or interpret the document's authority.

**OD-NATIVE-01:** `cmd/mac-keyvault-enclave/main.swift: sign` accepts a digest,
blob, presence mode and short reason. It has no document byte buffer, full-text
view, complete-layout acknowledgement, or explicit document-confirmation
handoff. It filters controls and clips the reason to 200 scalars. The existing
`cmd/mac-keyvault/confirm_dialog.go` is an SSH confirmation hook: its closed
request carries a fingerprint and digest/unlock time, and its dialog displays
only a digest prefix. It neither admits a document nor detects its truncation.
`internal/reviewedsession` also explicitly remains unconnected and supports four
typed grant profiles, not arbitrary UTF-8 document consent.

Consequently `Prepared.SignFile` and `owner-document sign` return the visible
`owner-document-native-unavailable` refusal on **every platform**, before manager
construction, custody lookup, helper execution or UI. They do not fall back to
`sign --data-file`, `signer serve`, osascript, stderr output, a matching hash, or
an unauthenticated confirmation callback. This refusal is the actual remaining
contract/implementation blocker, not an owner-key provisioning request. No native
success, installed qualification or owner consent is claimed by the tests.

## Available public source operations

Inert syntax, using an independently accepted build and public synthetic inputs:

```text
swarma-keyvault owner-document review --document FILE --owner-spki-der FILE
swarma-keyvault owner-document verify --document FILE --owner-spki-der FILE --signature FILE
swarma-keyvault owner-document sign --document FILE --owner-spki-der FILE
```

`review` emits an explicitly unsigned full rendering. `verify` is public-only;
it accepts an existing detached signature and asserts only its exact-byte
cryptographic validity. `sign` always refuses as above. Repeated, unknown and
inapplicable options, positional extras, stdin selectors and empty paths refuse.
No command creates a key, writes a signature file, activates a grant or contacts
a provider. On nonzero exit discard any partial redirected review/output.

The document must be a nonempty regular file, at most **16,384 bytes**, **256
logical lines** (a terminal LF counts an empty final logical line), **160 Unicode
scalars per line**, with at least one visible character. File reads refuse
symlinks, special files, over-limit data and detected replacement/size/mtime
changes. Linux/macOS open with `O_NOFOLLOW|O_NONBLOCK` so a swapped FIFO cannot
block the read. Other platforms refuse the file route. These checks do not
create a hostile-same-UID filesystem isolation boundary or prove history when a
writer changes bytes and restores them between observations.

The deliberately bounded display alphabet is printable ASCII, Russian `А-я`,
`Ёё`, and `«»–—‘’“”…№`, plus ASCII space and LF. Controls, ESC, CR, tabs, bidi,
zero-width, combining marks, other scripts/symbols, non-ASCII whitespace and
leading/trailing/repeated spaces refuse. Blank lines and presence/absence of a
terminal LF are retained. The renderer's literal `BEGIN DOCUMENT`, `END DOCUMENT`
and `UNSIGNED exact UTF-8 document;` markers refuse within the input so it cannot
impersonate a review boundary. A refusal never normalizes the file to make it fit.
This conservative admission is not native font/visibility qualification.

The rendering gives byte count and terminal-LF state, followed by **all** original
document bytes. Its explicitly labelled separator LF is outside those bytes.
It never inserts ellipses, reformats lines or replaces text with a hash.
Short/error writes terminate rendering. The CLI rechecks the source bytes after
rendering and after verification, before reporting success.

## Ready composition and required next acceptance

`internal/ownerdocument` owns copied document/public buffers and compares full
bytes at every source check. Its **package-private, production-disconnected**
`signWithReview` composes the existing key-aware manager gate with a proposed
complete-review interface for synthetic tests. It checks source bytes before
review, compares the complete confirmed buffer, rechecks source and cancellation
immediately before private dispatch, then rechecks and independently verifies
before releasing detached DER. Every wrong key/address/generation/store/presence/
extraction, altered/truncated confirmation or pre-dispatch cancellation refuses
without a private call. After final admission, any failure withholds output and
is labelled outcome-unknown, without retry. Returned bytes alone are **not** an
authenticated acknowledgement of visibility or human intent. This interface is
readiness source; it is deliberately not an exported signing-admission API.

OD-NATIVE-01 is resolved only by a separate reviewed source change that:

1. Supplies a concrete source/artifact-bound native review/confirmation adapter
   and its custody/launch interface. It must display the complete admitted UTF-8
   bytes as plain text, distinguish document data from trusted UI, detect layout
   overflow/missing glyphs/unsupported rendering and refuse rather than truncate.
2. Binds the displayed, explicitly confirmed, signed and verified owned byte
   buffer to the fixed actual owner key and full digest, with final source-byte
   and cancellation checks. An adapter-supplied digest/boolean is insufficient.
3. Installs a final reason/key/digest check at native dispatch, including the
   actual key suffix and the Swift filter/200-scalar behavior. Existing generic
   `Describe` callbacks and fallback text confer no such guarantee.
4. Preserves no-retry/unknown-outcome handling on interruption, backend failure,
   changed source, failed verification and output failure after private dispatch.
5. Passes fresh independent exact-head review, checks and Sirius disposition.
   Separately authorized Mac rebuild/native visibility/presence/cancel/adoption
   must then validate the exact binary/helper pair. This source task authorizes
   none of those live operations and no merge.

Deterministic synthetic tests use public toy scalar/nonce constants, an in-memory
review sink and fake manager backend. They exercise exact bytes/newlines,
full rendering far beyond reason length, bounds/UTF-8/display refusals, strict DER,
tampering, review/confirmation/private-call/verification order, wrong key policy,
source mutation and cancellation. Positive synthetic signatures are explicitly
not macOS/Touch ID success. Public CLI tests also assert that the unavailable
signing route emits no signature and never constructs an issuance manager.
