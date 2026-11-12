# Namecoin native internal components

The native custody target is macOS. These internal source components do not add
an available Namecoin transaction command. There is no Namecoin PSBT, raw-digest,
account-unwrapping, journal-initialization or reconciliation dispatch operation
in the Swift helper. Existing P-256, document and recovery routes retain their
interfaces. Source preparation does not qualify Touch ID, Keychain isolation,
installed code identity, native durability or transaction signing.

## Process exclusion

`internal/namecoinlocalgate` owns one fixed `AF_INET` TCP listener at
**127.0.0.1:47739**. Host monitoring should classify it as a finite, local
Namecoin exclusion listener, rather than a node transport or RPC service. It
never accepts connections or reads/writes application data. There is no daemon,
address/port setting, inherited-descriptor API, alternate lock, retry or fallback.

Acquisition creates a low-level socket, disables and reads back `SO_REUSEADDR`
and `SO_REUSEPORT`, binds, listens and verifies both options again. Close-on-exec
is set under the Go fork lock and verified. `EADDRINUSE` returns the fixed
`account_busy` refusal; other admission errors return `local_gate_unavailable`.
No operating-system error text is returned. A squatter can deny availability;
that is never permission to use a different exclusion object.

Every future transaction/reconciliation helper must acquire its own guard before
reading either the anchor or journal. It must retain the guard through private
use, result handling, durable state completion and private-buffer cleanup. The
same process must perform private transaction work; a parent-held or inherited
listener is insufficient. Selected-item adoption uses the same gate for its own
finite read/mutation/readback phase and releases it before launching a helper;
the helper must independently acquire and reload. Those are separate operations,
not one atomic transaction. The current internal package is not yet linked into
a Namecoin engine.

The tests use real paired processes and a public simulated effect counter. They
cover a replaced/unlinked disposable filesystem lock/root, different request IDs
with the same simulated outpoint, both actual reuse options off, all four reuse
attempt combinations, a squatter, a stopped holder and process death. No socket
traffic or cryptographic private use is needed. A second acquisition after release
is a liveness control; it does not authorize replay. The crash fixture preserves
only a public simulated fence and proves no native authenticated recovery. Run
only one fixed-port witness binary at a time in the authorized serialized lane;
an occupied port is a refusal/failure, not a passing skip.

## Immutable native review

`NamecoinReviewSnapshot` owns value copies of the operation, account, fee, exact
review-frame digest and rendered parsed facts. It receives the frozen frame and
facts from the future trusted in-process engine; it does not parse a facade
request or define a replacement wire/review frame. Integration must validate the
frame/fact relationship and supply all semantic fields from the same owned parse:
network/genesis, selected group/account/public pins, plan/phase and lineage,
transaction version/locktime, every input/outpoint/amount/script/path/sequence,
every output/value/script/path, complete name operation/opening/value, fees,
policy/release facts and exact unsigned transaction bytes as applicable. A digest
or caller-authored summary alone cannot supply that contract.

The AppKit window renders every supplied fact with its exact byte count, escaped
ASCII and complete hexadecimal bytes. Control/non-ASCII bytes and backslashes
are escaped in the readable representation; no value can inject review framing.
Hexadecimal lines contain all bytes. Text wraps without elision, and full
character/glyph/layout checks refuse an incomplete display. Cancel, missing
display/font glyphs, overflow or failed consent ends the operation. Scrolling to
the end makes the full text available; it cannot prove the person read it.

Only after complete native confirmation does the internal biometric primitive
create a fresh `LAContext`, request biometrics without password fallback, use the
full operation/account/fee/64-digit SHA-256 reason, invoke its in-process operation
and invalidate the context on every exit. It does not clip the reason or return a
consent boolean/token. Exact OS prompt presentation still requires attended native
qualification. No public operation currently reaches this primitive, and no
signing capability is claimed from its existence.

Journal initialization has a separate operation label/review and fresh biometric
context inside the first post-review owner adoption sitting. It signs no
transaction. A later spend needs its own complete review and fresh presence.
Ordinary signing and reconciliation never initialize absent state. No public
reset or generic unwrap operation is introduced.

## Journal integrity and replay model

`internal/namecoinjournal` is a pure internal codec and state model. It has no
filesystem or Keychain backend, no installed state selection and no native call.
Its local binary formats (`KVNA1`, `KVNF1`, `KVNS1`, `KVNT1`, each followed by a
zero byte) are not facade wire formats. There is no JSON/PSBT endpoint for them.

The account integrity KDF is HKDF-SHA256 with scalar32 big-endian followed by
chaincode32 as input. Its salt is SHA256 of ASCII
`keyvault/namecoin-journal-salt/1`, zero, LP(group), LP(account), public pin-file
hash32. Info is ASCII `keyvault/namecoin-journal-anchor/1`, zero. Output is32
bytes. LP means u32 big-endian byte length followed by exact bytes. The protected
head token is HMAC-SHA256 over ASCII `keyvault/namecoin-journal-head/1`, zero,
LP(group), LP(account), public pin32, LP(policy revision), sequence u64 big-endian,
head32. Policy is bound by the token, not added to the specified KDF salt.

The public locator is lowercase SHA256 of LP(group), LP(account). Local genesis
is SHA256 of ASCII `keyvault/namecoin-journal-genesis/1`, zero, followed by those
length-prefixed identities, pin32 and LP(policy). Each physical frame binds a
strictly increasing sequence, predecessor hash and bounded body; the new head is
SHA256 of its complete encoded frame. The chain must reach exactly the existing
protected head, within 65,536 records and64 MiB. Typed history additionally checks
allowed attempt transitions. Opaque physical-chain consistency alone is weaker.

An anchor's encoded protected value includes the confined integrity key and token.
It is **secret**, for direct same-process storage in the qualified protected
Keychain item only; it must never enter a journal, receipt, pipe, argv or log.
Callers must clear temporary encoded/account buffers. Clearing Go buffers is best
effort, not a universal erasure guarantee. No serializer or KDF is a public oracle.

Stored-key MAC consistency does not authenticate a recreated anchor. Decoding
does not set the in-memory account-match fact, and signed reconciliation remains
UNKNOWN until account rederivation succeeds. That fact is never persisted or
supplied as a caller boolean. After fresh
biometric account use, the engine must independently rederive and compare the
expected integrity key before any ECDSA or authenticated reconciliation. The
journal key cannot derive account or child signing authority. Native tests must
qualify read/update/delete/recreate/change-ACL refusal or detection. Privileged
memory/whole protected-store rollback remains outside these checks.

A dispatched outpoint is fenced independently of the request ID. Complete signed
results retain their exact hash; dispatched and explicitly unknown attempts both
reconcile as UNKNOWN and cannot silently resume or release inputs. The pure model
performs no ECDSA or result-signature verification. The future engine must durably
persist/fsync the dispatched fence, update and read back the protected anchor,
rederive account integrity and only then sign. It must verify and persist the
complete result and final journal/anchor before reporting success. Partial writes,
a missing anchor after adoption, corruption or a mismatched head require UNKNOWN
or refusal, never empty initialization, automatic repair, truncation or re-signing.
Keychain readback is not atomic compare-and-swap; kernel exclusion is a separate
requirement. Power-loss behavior needs actual native qualification.

## Linked sidecar and preserved pair

The separate sidecar binds the public group ID, physical recovery group, logical
Nostr and Namecoin identities, both public pin hashes, policy and exact hashes of
the existing paired metadata and ciphertext bytes. The Nostr identity must retain
the physical group's service; the Namecoin identity may use its existing separate
service. Verification compares exact supplied bytes without parsing/re-encoding
or modifying the pair. No purpose is rewritten, rewrapped or recreated. A public
sidecar hash alone establishes neither selected-item identity nor custody.

Selected-item adoption must additionally compare the exact item reference,
metadata, old/new sole-application ACL structure, helper identity and both public
purpose pins at mutation/readback. The sidecar does not perform that adoption.
There is no grant derivation, new grant purpose, grant presence-policy assumption
or account/root export in this component. Native anchor/sidecar adapter source is described below. Engine linkage and
selected-item adoption remain dependent on the generated in-process ABI and
attended qualification.

## Validation bounds

Go tests include public literal KDF/MAC vectors calculated independently from the
written frame contract, anchor substitution/tamper/truncation, physical versus
typed history, different-request replay, partial-effect mismatches and exact
paired-byte preservation. Those controls establish only their exercised pure
contracts. Kernel tests separately exercise real sockets/processes when executed.
Neither proves native owner presence, protected storage or usable signing.

This source unit permits formatting and static diff checks only. Go builds/tests,
Swift compilation, native executable runs and codesign require the separately
serialized test-lane release. Codesign additionally requires immediately preceding
host-watch confirmation and the retained opt-in runner. Native custody and
owner-presence qualification remain separate attended operations after independent
review. No unexecuted test is a passing result.


## Finite native storage adapter source

`cmd/mac-keyvault-enclave/NamecoinJournalStorage.swift` implements a finite macOS
adapter for the new journal item. It is source prepared for the linked custody
helper, with no public dispatcher or exported C ABI. The current standalone build
still compiles only `main.swift`; the linked build must explicitly include this
file and `NamecoinJournalOperations.swift`. Source-list integration is separate
from native qualification.

The selection freezes the existing physical group, logical Namecoin account,
public pin, policy, qualified helper CDHash and complete local linked sidecar.
The locator matches the Go length-framed group/account hash. The sidecar must
match the selected binding and preserve the physical group/Nostr service relation.
It is public metadata, not an authority supplied by an untrusted request.

Only the fixed service `works.relux.mac-keyvault.namecoin-journal.v1` and this
locator are queried in the operating-system account's login Keychain. The adapter
uses the OS account database rather than environment HOME or a changed default
Keychain. It provides no enumeration, arbitrary selector, delete, reset, paired
item read or paired item ACL operation. Noninteractive Keychain access remains
required; a locked/refused store is not an invitation to expand trust.

Before opening the adapter, source checks the actual running helper with strict
code validity, the exact qualified CDHash, the existing hardened/ad-hoc flag
allowlist, live valid/runtime flags, no debugged flag and absent/empty
entitlements. Decrypt access on the selected new anchor must list only the current
helper on every matching decrypt ACL. Item metadata must match exactly. These
source checks do not qualify the platform's update/delete/change-ACL behavior.

The linked public sidecar resides only in the NEW item's generic attribute,
framed with schema `keyvault-namecoin-journal/1`, the selected binding, helper
CDHash and sidecar. The comment is the exact schema, and account/label are the
locator. The protected anchor value remains secret. This placement adds no new
purpose to the paired recovery record and changes none of its ciphertext,
metadata, names, generations or public pins.

Initialization is create-only `SecItemAdd`, with a new sole-helper `SecAccess`.
Existing/conflicting state refuses. A successful mutation is followed by an
exact persistent-item-reference, metadata, ACL and byte readback. Ordinary anchor
replacement uses `SecKeychainItemModifyAttributesAndData` with no attribute list;
it compares the expected existing secret bytes and selected persistent reference,
requires one sequence advance and the same integrity key, updates only the value
and performs exact readback. It never replaces an ACL or metadata. This is not
compare-and-swap; the engine must already hold its process-owned kernel gate.
An attempted mutation or post-mutation readback failure is UNKNOWN. Duplicate
create refuses without overwrite. No automatic retry/rollback is implemented.

Native format checks admit only the exact `KVNA1` binding and bounded protected
layout. Initial state must have sequence zero and the exact local genesis head.
These shape checks cannot authenticate a key/token. The linked engine still must
verify its MAC, account public pin and independently rederived integrity key
before private use or authentic reconciliation. Swift does not implement a
parallel KDF or substitute its shape check for the Go engine.

Secret input is borrowed synchronously from compiler-resistant-cleared owned
memory; no Swift secret `Data` copy is made for `SecItemAdd`. Framework-owned
secret memory is cleared with `memset_s` before the framework frees it. Expected
secret-value comparisons use the SDK's `timingsafe_bcmp`. The owned-buffer type
has fixed opaque descriptions, invalidates on clear and is not Sendable. It
provides no pointer transfer/free protocol or exported ABI. The storage adapter itself creates no crypto private-key objects. The operation
layer below scopes hardware/shared/symmetric CryptoKit objects to one call;
the installed public CryptoKit interface provides no explicit zeroing primitive
for those objects. It does not serialize them to try to wipe them. Supported
Go crypto-library key-object zeroing and every owned Go account/child/intermediate
buffer remain the archive's obligations. No child process is spawned by the new
native source, and no universal OS/library memory-erasure guarantee is made.

`NamecoinJournalOperations.swift` assembles immutable local native initialization
and reconciliation documents. The local review domain is
`keyvault/namecoin-journal-native-review/1`, zero, followed by LP(operation),
LP(exact public native metadata) and the reviewed adoption-plan digest32. This is
not a transaction/facade review frame. Initialization performs separate complete
review and fresh biometry, unwraps the existing selected encrypted account inside
the same helper, then borrows only its64 scalar/chaincode bytes to the linked
engine for genuine account-pin/KDF/genesis verification. It creates/readbacks the
anchor and clears the owned value. Return from this native phase is not full
initialization/adoption readiness: the archive still must finish its durable
filesystem/readback/receipt lifecycle under the gate. Its engine action has no ECDSA role.
Reconciliation freezes exact anchor bytes and item reference before review,
creates its own fresh context, refuses changed state, unwraps the selected account
and authenticates only the frozen bytes. It cannot initialize or mutate the
journal.

The internal sealed-account type accepts only the existing181-byte Namecoin
recovery envelope and its independently selected wrapping point/recovery binding.
It loads the Enclave wrapping key using this operation's actual context, checks
its public point, performs the existing X9.63/AES-GCM opening, and admits only the
exact100-byte `KVN1` frame with matching recovery binding. The64 account bytes are
borrowed synchronously; they never become a parent response, String, diagnostic,
file or argv. Owned symmetric intermediate and plaintext buffers are cleared
using `memset_s` inside their mutable borrows on both success and failure. The
internal primitive is file-scoped to initialization/reconciliation and adds no
raw account operation. Existing wrapping-policy qualification is still required;
software framing alone is no Touch ID witness. The Go archive must still verify
the independently trusted account pin before accepting those account bytes.
Storage/engine refusals propagate without being mislabeled as biometric errors,
especially when an attempted mutation is UNKNOWN.

The engine actions are not yet wired to C: the generated versioned header and
exact ABI compatibility fixture must precede that work. The native initialization
entry remains internal and must be admitted only by the first post-review
adoption sitting's engine lifecycle. No caller boolean or public reset operation
supplies that permission. The displayed adoption-plan digest binds the selected
public plan; it does not prove that adoption or owner review occurred. The engine
lifecycle must establish the actual admitted first sitting. Exact existing-attempt/result selection and public
reconciliation output remain the frozen engine's work; the source primitive
alone is not a usable signer or authenticated-result endpoint. Eventual C exports
must recover panics into closed refusals and retain UNKNOWN after DISPATCHED.

The paired item's decrypt principal remains the qualified Go vault, never the
helper. Rebuilding that vault requires a finite attended old-to-new sole-principal
adoption unless qualified unchanged-identity evidence proves it unnecessary.
The separate finite adoption source uses `SecKeychainItemSetAccess`; its
selected-reference, complete attribute/value preservation, authorization and
readback behavior still require disposable qualification. The journal adapter
does not change the paired ACL. The owner sitting includes that
adoption when required, then explicit initialization; a spend gets separate
fresh review/presence. There is no implicit old-plus-new or helper trust interval.

## Native software controls and remaining qualification

`NamecoinJournalStorageTests.swift` uses Swift Testing and only public synthetic
model/memory fixtures. It does not construct the real storage adapter, execute
Keychain/code-identity/biometric calls, simulate hardware success or substitute a
callback returning true. It checks fixed public framing vectors, positive and
forbidden retained identity forms, sidecar bounds and binding, immutable owned
buffers and closed error classification. Protected-anchor positive fixtures are
syntax-only and intentionally not authenticated tokens. The test target should
compile the storage/model source separately from `main.swift`, UI orchestration
and production dispatch; a target is not yet installed by this source change.

Native code identity and sole-app decrypt policy need real disposable native
controls. Update, delete, recreate and change-ACL boundaries need their actual
positive/refusal/UNKNOWN witnesses. Compiler/type/link compatibility, generated
header/architecture matching, real native layout/context/decline, durable
journal/anchor/result ordering and first-sitting lifecycle remain unqualified.
No software fixture proves owner presence or makes a public receipt an anchor.
The native adapter and tests have not been compiled or run in this source unit.

## Selected paired-item code adoption

The internal `recovery_adoption` source prepares and applies one selected paired
item transition. It supplies no CLI, facade dispatch, owner-consent boolean,
archive export, installed migration or generic Keychain administration route.
The owning typed operation must acquire the fixed exclusion gate before prepare,
freeze the complete public review document, display it fully to the owner and
obtain the separately admitted owner sitting before apply. It must retain that
gate through handle closure. The current source has no caller implementing this
owner flow; a prepared plan is review input and grants no invocation authority.

Selection is limited to the explicit OS-account login Keychain and the fixed
`works.relux.mac-keyvault.nostr.v1` generic-password service. One exact account,
canonical paired metadata, complete sealed value and persistent item reference
are mandatory. Existing v1 and v2 records, including equal and distinct v2 purpose
services, retain their current validators. Nothing selects another generation,
inventories the store, changes a default, reads an account plaintext or creates
a companion item. Ambiguous, missing, changed or noncanonical selection refuses.

Both old and new executable artifacts must independently pass actual strict
static signature verification for all architectures, the exact public CDHash,
`0x10002` ad-hoc/hardened flags and absent/empty entitlements. Physical executable
paths and stable file identity are checked around trusted-application creation;
a supplied path/hash is insufficient. Designated requirements must match Apple's
binary representation of the exact CDHash alone or conjoined with the actual
bounded ASCII identifier. Team, path-only, wildcard, disjunction and unconditional
requirements are outside that allowlist. The actual caller must separately match
one of the two qualified running identities. Native trusted-application data is
derived from the validated artifacts, frozen and re-derived at apply. These
checks require immutable artifact custody and disposable OS identity witnesses;
they do not prove resistance to a compromised same-user host or OS.

Preparation verifies that every decrypt entry contains exactly the old trusted
application and authorizes only decrypt. A mixed decrypt/other-authorization
entry cannot change its shared application list while preserving the other
policy and entry structure, so it refuses before mutation. Wildcard-any and
unsupported complex ACL forms also refuse. No entry is split, removed or rebuilt;
no helper, old-plus-new list, team or wildcard is installed. Every unrelated
application list remains exact, including null versus empty. Authorizations,
descriptions and the full CSSM prompt version/flags remain exact. Raw CSSM owner
subjects, delegation, entry handles/tags, validity and unrelated subject trees are
also snapshotted and checked. Only the decrypt subject's application substitution
is permitted; its complete simple contents remain bound. Failure to represent or
preserve a native form refuses rather than approximating it.

The private native plan frame (`KVAD1`) contains old/new actual trusted-application
data, the complete sorted attribute frame (`KVAT1`) and before/after ACL frames
(`KVAC1`, including the `KVAR1` raw preserved-state projection). Lengths are bounded
and framed with big-endian u32. These are local bridge formats, not the Namecoin
wire, a public API or a substitute for the generated engine header. The immutable
review document additionally binds the physical and both logical generations,
complete public metadata/pins, persistent reference, old/new paths/CDHashes,
entire sealed-value hash/size and each retained purpose ciphertext and opaque
wrapping representation hash/size. Its full digest binds the prepared write set.
The future native review must present these facts without truncation; the binary
document alone is not an implemented user review.

Apply is one-shot. It rechecks actual artifacts and exact selected state before
the sole persistent call, `SecKeychainItemSetAccess` on that item. It changes only
the decrypt applications in the original access object. Readback requires the
same persistent reference, every available generic-password attribute including
metadata and dates, the entire sealed value and the intended sole-new ACL state;
both purpose ciphertexts and identities therefore remain byte-equal. No value,
attribute, owner, unrelated ACL or prompt-setting write is issued. There is no
delete, reset, recreate, implicit grant, retry, rollback or trust-widening fallback.
A definite pre-mutation failure is a fixed refusal. Any attempted write followed
by failure, changed state or unavailable readback is fixed UNKNOWN, including
failure of the old caller to retrieve the value after losing decrypt authority.
Raw OS statuses, sealed data and metadata never enter error diagnostics. Owned
input copies are cleared, and framework-returned value memory is cleared with
`memset_s` before its matching free. No account is unsealed or signed.

The native API is not a compare-and-swap transaction. A cooperative held gate and
immutable artifact custody are required; a hostile independent writer can cause
refusal or UNKNOWN. The installed SDK does not establish whether actual emitted
ACL forms preserve their raw state/handles, whether changing access alters an
attribute such as modification time, or which admitted caller can read the
sealed value both before and after replacement with UI disabled. Those precise
positive/refusal/UNKNOWN witnesses require a separately admitted disposable
old/new identity lane before any retained-item owner operation. No currently
installed old executable is assumed to contain this new primitive. A complete
attended execution/custody path still needs integration and qualification; this
source does not claim that rebuilding an old executable preserves its identity.

`recovery_adoption_test.go` contains portable source controls for retained record
compatibility, immutable selection/review bytes, independent public literal
framing/digest vectors, exact application-list substitution, forbidden changes,
mixed decrypt refusal, truncation/length bounds and conservative outcome mapping.
Its ACL/app fixtures are synthetic public bytes, not real trusted applications.
They do not mock native success or prove authorization, actual native preservation,
owner consent or Touch ID. Compilation, tests, Keychain mutation/readback and
native identity qualification remain unexecuted for this source unit.
