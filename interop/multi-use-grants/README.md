# Multi-use owner grants: interop vectors

These vectors fix how a receiver on any platform must judge multi-use
(`once` / `until_expiry`) owner grants and the requests made under them. The
interaction contract is [CONTRACT.md](CONTRACT.md).

Pins:
- swarma-envelope `6c71e5226416`: records and the platform verifier, with publisher profile `grant-revocation-2`;
- a2a #189 `25f1e44b002b`: event projection;
- the `internal/mugrant` builders of this repository.

## Keys

`keys.json` lists the test keys. Each private scalar is
`SHA-256("swarma-keyvault mu-interop seed/1 " + name)`, used as a raw P-256 private scalar or as an Ed25519 seed, per the key's algorithm.
These are test keys only. Never use them for anything else.

| Name | Role |
| --- | --- |
| `grant-root` | owner grant root (issues grants and attestations) |
| `foreign-grant-root` | another grant domain |
| `mac-agent` | Mac agent key under profile `mac-se-1` (the requester) |
| `stranger` | a key that signs where it must not |
| `publisher` | grant revocation publisher (`grant-revocation-1`) |
| `linux-agent` | Ed25519 Linux agent key (Keymaker v0 attestation) |
| `linux-stranger` | an Ed25519 key that signs where it must not |
| `keymaker-service-root` | Keymaker signing-service root (purpose 5) |
| `agent-revocation` | registry revocation key for agent keys |
| `publisher-ed25519` | Ed25519 grant revocation publisher (`grant-revocation-2`) |

## Case format (`swarma-keyvault/mu-interop-case/1`)

Each file in `cases/` holds one case:
- `id`, `claim` and, for a negative, `positive_control`;
- `pins`: the receiver's protected configuration;
- `records`: the exact signed grants, the agent and publisher attestations and any owner-root revocations in the receiver's configuration, as unpadded base64url bytes;
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
| `M-N-revoked-then-older` | revoking snapshot, then an older one without the entry | `revoked`, then `mu-grant-revoked` |
| `M-N-revoked-then-equal` | revoking snapshot, then one with the same `issued_at` without the entry | `revoked`, then `mu-grant-revoked` |
| `M-P-root-revocation-unmirrored` | an unrelated owner-root revocation the publisher does not mirror | `succeeded` |
| `M-N-module-outside` | only the module argument: outside the receiver's modules | `mu-request-out-of-owner-scope` |
| `M-P-room-membership` | none: `room.membership` in the receiver's room scope | `succeeded` |
| `M-N-room-outside-scope` | only the target id: a room scope the receiver does not serve | `mu-request-out-of-owner-scope` |
| `M-P-text-tab` | text containing TAB | `succeeded` |
| `M-P-future-then-fresh` | a validly signed snapshot dated 10 minutes ahead, then a fresh one | `key_binding_unavailable`, then `succeeded` |
| `M-P-incomplete-then-older` | a publisher-signed snapshot with `complete` false, then an older complete one | `key_binding_unavailable`, then `succeeded` |
| `M-P-oversize-then-older` | a publisher-signed, well-formed snapshot of 64 record entries over 8192 bytes, then an older one without them | `key_binding_invalid`, then `succeeded` |
| `M-N-refused-then-older-mark` | a request for another audience with a fresh snapshot, then a request with an older snapshot that drops nothing | `audience_mismatch`, then `mu-revocation-snapshot-rollback` |
| `M-N-snapshot-older` | older snapshot after a newer one, both under 60 s | `succeeded`, then `mu-revocation-snapshot-rollback` |
| `M-N-root-revoked` | owner-root revocation in the receiver configuration, publisher snapshot silent | `mu-grant-revoked` |

Linux-authored (Ed25519) family:
- Mac-issued grants name the Linux agent's Ed25519 key.
- The case adds `pins.linux` (service root, agent revocation key, registry identity).
- `registry` holds the attestations served by content id and the current active generation.
- Each step carries `agent_snapshot`.

| Case | Fact changed | Expected |
| --- | --- | --- |
| `L-P-accept` | none | `succeeded`, one effect |
| `L-N-wrong-key` | Ed25519 signature by another key | `envelope_signature_invalid` |
| `L-N-wrong-action` | action not in the grant | `mu-no-applicable-grant` |
| `L-N-attestation-expired` | Keymaker attestation expired, grant still valid | `key_binding_invalid` |
| `L-N-attestation-unavailable` | registry does not serve the referenced attestation | `key_binding_unavailable` |
| `L-N-generation-moved` | registry's active generation differs | `key_binding_invalid` |
| `L-N-agent-revoked` | fresh agent revocation snapshot revokes the key | `revoked` |
| `L-N-stale-agent-snapshot` | agent revocation snapshot 61 s old | `key_binding_unavailable` |
| `L-N-sender-not-registered` | sender MXID without a registry identity | `mu-sender-not-attested` |
| `L-N-agent-revoked-then-older` | revoking agent snapshot, then an older one without the entry | `revoked`, then `mu-grant-revoked` |
| `L-N-agent-revoked-then-equal` | revoking agent snapshot, then one with the same `issued_at` without the entry | `revoked`, then `mu-grant-revoked` |
| `L-N-registry-uid-mismatch` | the registry identity's uid differs from the active generation | `key_binding_unavailable` |
| `L-N-cross-algorithm` | the Linux identity names a P-256 Mac key and its `mac-se-1` attestation | `key_binding_invalid` |
| `L-N-agent-rollback-drops-unrelated` | newer agent snapshot drops an unrelated key it listed before | `succeeded`, then `mu-revocation-snapshot-rollback` |
| `L-N-agent-rollback-older-mark` | older agent snapshot after a newer one, revoking nothing | `succeeded`, then `mu-revocation-snapshot-rollback` |
| `L-N-replay` | same event twice | `succeeded`, then `mu-request-nonce-already-held` |

Ed25519 publisher family (r8): grants whose revocation publisher is an Ed25519 key appointed by the owner grant root (`grant-revocation-2`). The pins name that key and the records carry its attestation. The family has 15 cases with 19 steps (5 succeeded steps), 8 Mac-authored and 7 Linux-authored; the whole set has 88 cases with 108 steps and 24 succeeded steps.

| Case | Fact changed | Expected |
| --- | --- | --- |
| `P2-P-accept` | none: fresh snapshot signed by the Ed25519 publisher | `succeeded` |
| `P2-N-revoked` | the fresh snapshot lists the grant | `revoked` |
| `P2-N-snapshot-foreign-signer` | snapshot naming the publisher, signed by another Ed25519 key | `key_binding_invalid` |
| `P2-N-profile-2-p256-subject` | root-signed `grant-revocation-2` attestation over a P-256 key | `key_binding_invalid` |
| `P2-N-issued-by-service-root` | `grant-revocation-2` attestation issued and signed by the signing-service root | `key_binding_invalid` |
| `P2-N-snapshot-older` | older Ed25519 publisher snapshot after a newer one | `succeeded`, then `mu-revocation-snapshot-rollback` |
| `P2-N-profile-1-ed25519-subject` | root-signed `grant-revocation-1` attestation over an Ed25519 key | `key_binding_invalid` |
| `P2-N-unknown-profile` | root-signed publisher attestation of an unknown profile | `key_binding_invalid` |
| `P2-L-P-accept` | Linux author: fresh Ed25519 publisher and agent revocation snapshots | `succeeded` |
| `P2-L-N-revoked` | Linux author: the Ed25519 publisher snapshot lists the grant | `revoked` |
| `P2-L-N-publisher-is-agent-revocation-root` | Linux author: the publisher attestation's subject is the agent revocation root | `revocation_invalid` |
| `P2-L-N-publisher-is-service-root` | Linux author: the publisher attestation's subject is the signing-service root | `revocation_invalid` from `Authorize` |
| `P2-L-N-revoked-then-older` | Linux author: revoking publisher snapshot, then an older one without the entry | `revoked`, then `mu-grant-revoked` |
| `P2-L-N-snapshot-older` | Linux author: fresh publisher snapshot, then an older one | `succeeded`, then `mu-revocation-snapshot-rollback` |
| `P2-L-N-replay` | Linux author: same event twice under the Ed25519 publisher | `succeeded`, then `mu-request-nonce-already-held` |

The P2 negatives that expect `key_binding_invalid` (Mac author) or `revocation_invalid` (Linux author) would get the same code from a verifier that does not know `grant-revocation-2`. They show that profile 2 refuses what it must only together with `P2-P-accept` and `P2-L-P-accept`, which such a verifier refuses. A receiver that validates the pinned publisher attestation at configuration load meets the invalid-attestation cases by refusing that configuration (CONTRACT, publisher profiles).

New negative controls: the four Linux-authored P2 cases above name `P2-L-P-accept`. The Mac role-collision case `M-N-publisher-is-grant-root` names `M-P-accept`: a root-signed `grant-revocation-1` attestation whose subject is the grant root gives `key_binding_invalid` from `VerifyMessage`.

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

Not committed, run by hand against the real code: these known-violation plants each make `TestMUInteropVectors` fail at the intended case:
- edited event text in a positive case;
- an unknown member in a case file;
- the receiver's nonce check switched off;
- the receiver's text rule switched off;
- the agent revocation snapshot left out of the receiver's evidence;
- the snapshot high-water check switched off;
- the owner-root revocations ignored.
- the snapshot shape check left out of pre-verification recording;
- the 8192-byte snapshot bound left out of pre-verification recording;
- the mark raise left out of pre-verification recording.
- the pinned verifier set back to one without `grant-revocation-2` (`P2-P-accept`, `P2-N-revoked`, `P2-N-snapshot-older`, `P2-L-P-accept`, `P2-L-N-revoked`, `P2-L-N-revoked-then-older`, `P2-L-N-snapshot-older` and `P2-L-N-replay` fail).
- the foreign-journal-signer skips left out of pre-verification recording (the empty-journal positive control still records both pinned snapshots);
- the consecutive interrupted-attempt bound left out of the file-lock wait (a finite sentinel after the bound exposes the extra attempt; the free-lock and interrupted-then-success controls still acquire the lock).

Regenerating (`go run ./cmd/mu-interop-vectors -out NEW_DIR`) produces fresh
signatures. The committed files are the contract.
