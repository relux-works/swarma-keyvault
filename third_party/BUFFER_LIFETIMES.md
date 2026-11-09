# Named buffer lifetimes on Nostr paths

The ordinary Go build uses the existing precomputed base multiplier. Its
algorithm and BIP-340/RFC6979 derivations are unchanged. The table describes
explicit mutable storage, not a universal memory-erasure guarantee.

| Buffer | Owner and cleanup | Return-path evidence |
| --- | --- | --- |
| Vault scalar slice and private-key object | `signNostrSecretWithRandom` / `signNostrWithAux` defer slice clear and `PrivateKey.Zero`; generation transfers only the backend-owned stored copy | Root positive, wrong-key, malformed digest and entropy-refusal tests |
| Vault auxiliary arrays | Both vault functions defer clearing their separate arrays, including early refusals | Root refusal/auxiliary fixtures plus source lifetime inspection |
| Captured `CustomNonce` array | The option transfers one use to `signingBuffers.aux`; deferred cleanup clears the actual captured array; overwritten fresh options clear immediately | Actual captured-buffer checks, overwrite test, reuse/concurrent-refusal tests |
| Effective private scalar | `signingBuffers.private`, cleared by the unconditional deferred owner cleanup | Both signing paths, successful and early-refusal lifecycle tests; omitted-wipe control |
| Effective private encoding and RFC6979 private encoding | `signingBuffers.privateBytes` / `rfcPrivateBytes`, direct `PutBytes` into owned arrays, same deferred cleanup | Both signing-path lifecycle tests |
| Aux XOR hash `t` and nonce hash `rand` | Actual `chainhash.TaggedHash` output allocations retained by the owner and cleared on return | Aux-path lifecycle test checks both actual allocations after return |
| Nonce scalar, parity-adjusted nonce and response intermediate | `signingBuffers.nonce`, `effectiveNonce`, `response`; same unconditional cleanup; returned signature contains independent public values | Signing lifecycle tests; official BIP-340 signatures verify after cleanup |
| RFC6979 returned nonce | Ownership transfers from nonce generator to `signingBuffers.rfcNonce`; explicit zero after each attempt and deferred cleanup on final return | RFC6979 signing lifecycle and retained upstream tests |
| RFC6979 key encoding and current V/K outputs | `nonceBuffers.key`, `v`, `k`, deferred cleanup; replaced output storage cleared before losing ownership | Retries 0, 1 and 5; replacement tests; omitted-K-wipe control |
| RFC6979 HMAC pads and inner digest output | Named pads cleared by nonce owner; `hmacsha256.Sum` clears its owned inner output after writing it; oversized-key temporary cleared on return | Direct pad lifetime tests and unchanged upstream RFC6979 vectors; source inspection of internal digest temporary |
| Fast base-multiplier raw encoding `kb` | `PutBytes` into caller-owned array; unchanged table traversal helper defers `zeroArray32` | Actual helper-buffer test with independently fixed generator; omitted-wipe control; root independent public-point/boundary fixtures |
| Private serialization value-receiver copy | Existing receiver transfers to `serializePrivateCopy`, which defers `Zero`; output byte ownership transfers to caller | Receiver-copy lifecycle test and omitted-wipe control; original borrowed key remains usable |

The deferred signing owner is installed before option parsing and validation.
All normal/error returns in that function, including nonce-zero, commitment and
verification refusals returned by the unchanged signing algorithm, unwind that
owner. Later algorithm refusals with cryptographically negligible preconditions
are established by this control-flow audit, not falsely claimed as naturally
reached by the supplied fixtures. The actual observed refusal fixtures cover
malformed digest, zero private scalar and consumed auxiliary options.

Named output storage transfers to its caller deliberately: the signature is
public, the nonce is cleared by the signer, and serialized vault scalars are
cleared by the vault backend. No command exposes the latter storage.

Compiler copies, registers, arithmetic temporaries, SHA implementation state,
GC/stack history and Security.framework internals remain outside these explicit
buffer checks. Existing variable-time behavior is retained; these changes prove
no constant-time or local side-channel property. Public-only verification does
not require secret cleanup. TinyGo's alternative multiplier is not a qualified
vault target.
