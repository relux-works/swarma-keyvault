# Multi-use owner grants: interop vectors

These vectors fix how a receiver on any platform must judge multi-use
(`once` / `until_expiry`) owner grants and the requests made under them. The
interaction contract is [CONTRACT.md](CONTRACT.md).

Pins:
- swarma-envelope `939750828554`: records and the platform verifier;
- a2a #189 `25f1e44b002b`: event projection;
- the `internal/mugrant` builders of this repository.

## Keys

`keys.json` lists the test keys. Each private scalar is
`SHA-256("swarma-keyvault mu-interop seed/1 " + name)`, used as a raw P-256 private key.
These are test keys only. Never use them for anything else.

| Name | Role |
| --- | --- |
| `grant-root` | owner grant root (issues grants and attestations) |
| `foreign-grant-root` | another grant domain |
| `mac-agent` | Mac agent key under profile `mac-se-1` (the requester) |
| `stranger` | a key that signs where it must not |
| `publisher` | grant revocation publisher (`grant-revocation-1`) |

## Case format (`swarma-keyvault/mu-interop-case/1`)

Each file in `cases/` holds one case:
- `id`, `claim` and, for a negative, `positive_control`;
- `pins`: the receiver's protected configuration;
- `records`: the exact signed grants and the agent and publisher attestations, as unpadded base64url bytes;
- `events`: the delivered a2a events, each with the exact envelope and text bytes;
- `steps`: handled in order against one fresh receiver journal. Each step has a trusted `now`, the publisher snapshot that is current at that time, and the `expected` verdict.

A verdict is `succeeded` for an executed request. Otherwise it is the exact refusal code:
- a platform code from the swarma-envelope verifier, or
- a receiver code (`mu-…`).

The authenticated sender of every event is `pins.sender_mxid`. The receiver fills
the Mac agent's active-generation MXID from it, never from the request.

Every negative differs from its positive control in one fact. The positive
controls stop an implementation that refuses everything from passing.

## Families

| Case | Fact changed | Expected |
| --- | --- | --- |
| `M-P-accept` | none | `succeeded`, one effect |
| `M-P-until-expiry-second-use` | second request, new nonce | `succeeded` twice |
| `M-N-wrong-key` | signature by another key | `envelope_signature_invalid` |
| `M-N-wrong-action` | action not in the grant | `mu-no-applicable-grant` |
| `M-N-wrong-target` | target not in the grant | `mu-no-applicable-grant` |
| `M-P-account-own-owner` | none: `account.manage` on an account the owner holds | `succeeded` |
| `M-N-account-other-owner` | only the account argument: another owner's account | `mu-request-out-of-owner-scope` |
| `M-N-audience-mismatch` | request audience differs | `audience_mismatch` |
| `M-N-room-mismatch` | request room differs from the delivering room | `message_room_mismatch` |
| `M-N-recipient-mismatch` | request recipient differs | `message_recipient_mismatch` |
| `M-N-lifetime-over-120s` | `exp - iat` is 121 s | `envelope_malformed` |
| `M-N-ambiguous-grant` | a second pinned grant also covers the request | `mu-ambiguous-grant` |
| `M-N-text-rule-before-hash` | text breaks the rule and the hash | `mu-request-text-refused` (the text rule runs first) |
| `M-N-expired` | grant interval ended | `expired` |
| `M-N-revoked` | fresh snapshot revokes the grant | `revoked` |
| `M-N-foreign-domain` | grant from another root | `key_binding_unavailable` |
| `M-N-stale-snapshot` | snapshot 61 s old | `key_binding_unavailable` (the author attestation check reads the same snapshot first) |
| `M-P-text-at-limit` | text of exactly 4096 bytes | `succeeded` |
| `M-N-text-over-limit` | text of 4097 bytes, bound by the signature | `mu-request-text-refused` |
| `M-N-text-cr` | text with CR, bound by the signature | `mu-request-text-refused` |
| `M-N-text-<class>` | one forbidden class each, bound by the signature: `nul`, `del`, `c1`, `fffd`, `invalid-utf8`, `blank`, `ideographic-space`, and every bidi control `bidi-061c`, `bidi-200e`, `bidi-200f`, `bidi-202a` … `bidi-202e`, `bidi-2066` … `bidi-2069` | `mu-request-text-refused` |
| `M-N-body-hash` | delivered text edited | `message_text_mismatch` |
| `M-N-replay` | same event twice | `succeeded`, then `mu-request-nonce-already-held` |
| `M-N-use-refill` | `once` grant, second request | `succeeded`, then `mu-grant-use-already-held` |
| `M-N-snapshot-rollback` | newer snapshot drops a held revocation | `succeeded`, then `mu-revocation-snapshot-rollback` |

The Linux-authored (Ed25519) family follows once contract decision D1 is agreed.

## Checking

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 scripts/keyvault-test-confined.sh -run TestMUInteropVectors ./internal/grants/ -count=1
```

The check runs every step through the pinned platform verifier and the KV
receiver. It also confirms that effects run exactly once per succeeded step and
that every positive control exists and succeeds.

Another implementation runs the same files and must give the same verdict per
step. When it disagrees, the spec decides.

Committed: `TestMUInteropRejectsDegenerate` shows that the set rejects degenerate implementations. A verifier that refuses everything fails every positive step; one that accepts everything fails every negative step that expects a verifier, text or grant-selection refusal.

Not committed, run by hand against the real code: these known-violation plants each make `TestMUInteropVectors` fail at the intended case, and their logs are kept in the task scratch:
- edited event text in a positive case;
- an unknown member in a case file;
- the receiver's nonce check switched off;
- the receiver's text rule switched off.

Regenerating (`go run ./cmd/mu-interop-vectors -out NEW_DIR`) produces fresh
signatures. The committed files are the contract.
