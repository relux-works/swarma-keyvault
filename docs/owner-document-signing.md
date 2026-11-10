# Exact owner document signing

The source provides a typed macOS full-document review and signing route. It is
pending independent review and qualification of the exact installed Go/native
helper pair. No Linux fixture establishes human visibility, consent, Touch ID,
Secure Enclave enforcement or native adoption. No installation or live owner
signing is authorized by these source tests.

## Existing key and signature contract

Supply an exact `SERVICE/grants-owner-v1` address and generation. The signing
key must be P-256 in Secure Enclave, with user presence and extraction `none`.
The independent exact SPKI DER pin must match the resolved public key.
A supplied public file establishes neither registry provenance nor ownership.

The signed value is SHA-256 of the **unchanged document bytes**. Output is the
existing detached P-256 strict low-S DER signature, independently checked against
the public pin before release. There is no new grant, envelope, domain prefix,
canonicalization or external signature format. A document signature confers no
platform authority and does not select a grantee or draft delegation text.

## Public operations

Inert syntax for an independently accepted build and public synthetic inputs:

```text
swarma-keyvault owner-document review --document FILE --owner-spki-der FILE --owner-key SERVICE/grants-owner-v1 --owner-key-version N
swarma-keyvault owner-document verify --document FILE --owner-spki-der FILE --owner-key SERVICE/grants-owner-v1 --owner-key-version N --signature FILE
swarma-keyvault owner-document sign --document FILE --owner-spki-der FILE --owner-key SERVICE/grants-owner-v1 --owner-key-version N
```

`review` emits explicitly unsigned full text. `verify` is public-only and checks
an existing signature against exact bytes. Neither accesses custody. `sign`
requires macOS and the matching native helper; other platforms visibly refuse
before constructing custody. No route creates a key, writes a signature file,
activates authority or contacts a provider. Repeated, unknown or inapplicable
options, positional extras, stdin selectors and empty paths refuse. On nonzero
exit discard any partial redirected output. A failed signature output write is
an unknown outcome; never automatically retry it.

## Admission and immutable bytes

Input must be a nonempty regular file, at most **16,384 bytes**, **256 logical
lines** (a terminal LF counts an empty final logical line), **160 Unicode scalars
per line**, and contain a visible character. Reads refuse symlinks, special
files, oversize data and detected replacement/size/mtime changes. Linux/macOS use
`O_NOFOLLOW|O_NONBLOCK`; other file platforms refuse. This does not isolate a
hostile process with the same user ID or prove unobserved filesystem history.

The deliberate display alphabet is printable ASCII, Russian `А-я`, `Ёё`, and
`«»–—‘’“”…№`, plus ASCII space and LF. Controls, ESC, CR, tabs, bidi, zero-width,
combining marks, other scripts/symbols, non-ASCII whitespace and leading,
trailing or repeated spaces refuse. Blank lines and terminal-LF state remain
unchanged. Literal `BEGIN DOCUMENT`, `END DOCUMENT` and
`UNSIGNED exact UTF-8 document;` in the input refuse renderer impersonation.
Nothing is normalized, clipped or replaced with an ellipsis to gain admission.

`Prepared` owns copies of the full document and public pin. Full byte equality,
not a digest supplied by an adapter, governs the source rechecks. Public review
includes every original byte and labels its framing separator separately.
Short or failed review writes refuse. These conservative admission rules alone
are not native font or layout qualification.

## Native review, confirmation and final dispatch

`Prepared.SignFile` constructs an Enclave-only manager after admission. It never
constructs a login-Keychain backend or falls back to generic digest signing,
SSH confirmation, osascript, stderr text or an external boolean callback.
`Manager.SignOwnerDocument` uses a dedicated typed backend method after normal
resolution, metadata, operation and expiry policy checks. The actual generation,
store, presence policy, extraction and exact SPKI are checked at that gate.

The existing sibling `mac-keyvault-enclave` helper is launched by its absolute
path after the existing ownership, regular-file and write-permission checks.
The complete byte buffer, full digest, resolved canonical key label, actual public point, exact SPKI pin and
exact reason travel over private stdin/stdout pipes. This internal two-stage
exchange changes no public signature format. Each frame is bounded to 64 KiB;
the complete interaction is capped at five minutes, without a retry.

The Swift helper owns one immutable `DocumentPlan` in one process:

1. It independently admits the complete UTF-8 buffer, recomputes its SHA-256,
   validates the canonical label and reason derived from that label and checks that the blob's public point and exact DER SPKI
   match the displayed identity. This is public inspection, with no signing
   probe or presence prompt before review.
2. AppKit presents all admitted bytes as plain, noneditable text inside a
   bordered scroll view, separate from trusted identity controls. The header
   identifies the key, full public-SPKI SHA-256, full document SHA-256, byte
   count and terminal-LF state. It uses a fixed monospaced font without
   ligatures, checks Core Text glyph coverage and complete TextKit layout, and
   refuses missing glyphs, insufficient screen width or layout overflow. It
   does not wrap or truncate a line to fit. A window must fit on screen to
   confirm. Long documents remain fully available through vertical scrolling.
3. Confirmation needs the end of the complete view to have been reached, a
   separately unchecked consent box, and an explicit confirmation button.
   Cancel/Escape/window close refuses. Scrolling is not evidence of reading.
   The view's entire UTF-8 buffer and layout are rechecked at confirmation.
4. Only after that consent does the helper emit a complete confirmed binding.
   Go compares every byte and identity field, rereads the custody record/blob/
   public point, and rechecks source bytes and cancellation. It then sends the
   full binding back as final dispatch to that same helper process.
5. Swift compares that dispatch to its immutable plan. Only then does it check
   presence enforcement and construct the fresh authentication context. The
   full reason, including the actual key suffix and all 64 digest hex digits,
   is validated below 200 scalars and used unchanged. This route never uses the
   generic helper's reason filter or clipping behavior.
6. After presence authentication, Swift verifies its signature against that
   exact public key and digest. Go validates and normalizes the existing DER
   representation, rechecks source/cancellation and independently verifies under
   the original SPKI pin before release.

Malformed/truncated/mismatched confirmation, cancellation or a final source or
custody change prevents private dispatch. EOF, timeout, interrupted pipes,
backend errors, failed verification and post-dispatch source changes release no
signature and cause no retry. For conservative reporting, every failure after
backend admission is labelled outcome-unknown, including failures that the
source controls demonstrably refused before signing. SIGINT/SIGTERM cancel the
CLI context and native child; losing output after signing remains uncertain.

The launch permission checks are not cryptographic attestation against a hostile
same-user replacement. Independent source/custody approval and qualification of
the exact signed Go/helper artifacts remain required before activation. An old
helper has no `review-document` operation and cannot satisfy the handoff.

## Verification and remaining native qualification

Public toy scalar/nonce fixtures exercise the production typed store/manager
boundary, complete bytes far beyond reason length, exact ordering, identity and
reason tampering, source/custody changes, cancellation, signature verification
and unknown outcomes. Private synthetic process peers exercise the real pipe
framing, timeout, error preservation and final dispatch. They are deliberately
not installed native helpers or owner keys, and supply no human-consent proof.

The native source uses Apple's primary APIs:
[Core Text glyph coverage](https://developer.apple.com/documentation/coretext/ctfontgetglyphsforcharacters(_:_:_:_:)),
[complete TextKit layout](https://developer.apple.com/documentation/appkit/nslayoutmanager/ensurelayout(for:)),
[glyph range](https://developer.apple.com/documentation/appkit/nslayoutmanager/glyphrange(for:)),
[used rectangle](https://developer.apple.com/documentation/appkit/nslayoutmanager/usedrect(for:)),
and [AppKit modal review](https://developer.apple.com/documentation/appkit/nsapplication/runmodal(for:)).
API documentation informs the implementation; it does not qualify this build.

A separately authorized macOS gate must compile the Swift/AppKit/CryptoKit
helper and the Go frontend, bind their exact artifacts to the reviewed source,
validate complete English/Russian display, every accepted glyph, blank lines,
terminal-LF identity, long documents, insufficient screens, consent and each
cancel/timeout transition, and confirm actual presence and signature verification.
It must use the existing accepted owner profile without creating/substituting a
key. The Linux Go cross-build does not compile Apple frameworks or prove any of
those runtime properties. Fresh independent exact-head review, required checks
and source/native custody disposition remain open; tests are not acceptance.
