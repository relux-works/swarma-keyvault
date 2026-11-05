# Multi-use owner grants: cross-platform interop contract (r2, draft for agreement)


Owner, 2026-11-05 16:51 MSK: «наши только доверенности под мак довести и чтоб оин со стороны линкуса кросплатформ поддержали - наша отвественность».

Sides:
- **KV (Mac)**: the issuer, Mac requester, Mac receiver and revocation publisher (relux-works/swarma-keyvault);
- **L (Linux)**: the Linux keyvault with Ed25519 agent keys, a Linux requester and a Linux receiver.

## 0. Pins

| What | Pin |
| --- | --- |
| Record format and verifier | relux-works/swarma-envelope `939750828554` (spec `spec/swarm-envelope-2.md`, library `record`, `verifier`) |
| Transport projection | a2a-swarm #189 `25f1e44b002b`, record `a2a.event-envelope-input/1` |
| KV builders | swarma-keyvault `internal/mugrant` at the landed #22+#23 head |

Anything not stated here follows the pinned spec. Where this text and the spec differ, the spec wins and this text is a defect.

## 1. Roles and algorithms

| Role | Mac | Linux |
| --- | --- | --- |
| Owner grant root (issuer of grant/1, Mac agent and publisher attestations) | P-256, Secure Enclave, Touch ID (`alexis/grants-owner-v1`) | none; grants for Linux agents are issued on the Mac |
| Revocation publisher (one per grant domain) | P-256, Secure Enclave, no presence (`grant-revocation/publisher`) | none; L consumes the Mac publisher's snapshots |
| Agent (requester) | P-256, Secure Enclave, no presence; attestation profile `mac-se-1` signed by the grant root | **Ed25519**; Keymaker v0 agent attestation signed by the signing-service root (`service_root`, purpose 5) |
| Receiver | swarma-keyvault `grants mu-execute` | L receiver |

Signatures in records are raw: Ed25519 is 64 bytes; P-256 is `r||s` in 64 bytes with low S. DER inside a record is refused. A Mac signer emits DER low-S, and the assembler converts it.

## 2. Records (all `swarm-envelope/2`, envelope members exactly `body,id,signatures,version`)

Content id = `sha256:` + hex(SHA-256(tag LF CCJ-1(body))). The signing preimage is `tag LF CCJ-1({body,key,role,version})` (spec §2.2). Each signature is exactly `{key,role,sig}`.

### 2.1 grant/1 (multi-use)

- Body members, exactly: `actions, aud, caveats, depth, exp, expires, iat, issuer, min_assurance, nonce, not_before, parent, subject, targets, type`.
- `caveats` is exactly `{expires, lang:"caveats/v2", not_before, use}`, and `use` is `once` or `until_expiry`. A v2 grant without `use` refuses with `grant_use_missing`.
- `depth` is 0 and `parent` is null. `min_assurance` is `{level:"A2",presence:false}`.
- The interval is chosen per grant by the owner, with a hard cap of one calendar year. `iat = not_before`, and `exp = expires`.
- `nonce` is 16 CSPRNG bytes in base64url. `subject` is the agent key id: `p256:` for a Mac agent, `ed25519:` for a Linux agent.
- Vocabulary v2 is a closed allowlist.
  - Actions `work.assign`, `work.require`, `work.contract`, `work.prioritize`, `work.land-order` and `work.accept` apply to kind `product`.
  - `account.manage` applies to `account-scope`, and `room.membership` to `room-scope`.
  - A target id is an exact name with at most one `owner:` qualifier. Patterns are refused.
- Issuer-side binding (not a verifier rule):
  - the issuer refuses unless the grantee has a verified attestation under the expected root that covers the whole interval;
  - the issuer refuses unless the publisher attestation for the domain exists and covers the interval;
  - the grantee MXID shown to the owner comes from that attestation.

### 2.2 message/1 (request)

- Body members, exactly: `action, arguments, aud, author, author_attestation, body_sha256, exp, iat, nonce, room, target, to, type`.
- `body_sha256` is the hex SHA-256 of the exact event text bytes.
- Text rule, ONE rule for both sides:
  - at most **4096 bytes** of valid UTF-8, not blank;
  - LF and TAB are allowed;
  - CR, other C0, DEL and C1 controls, U+FFFD and bidi controls are refused.
- The requester refuses to sign text outside the rule. The receiver refuses it on receipt with `mu-request-text-refused`, before any other check, even when `body_sha256` binds it.
- The a2a carriage accepts more (about 45 KB of envelope). The transport is not the limit.
- Times: `exp - iat <= 120 s`, in whole seconds.
- Identifiers:
  - `room` is a room id (`!…`), never an alias;
  - `to` is the receiver MXID;
  - `aud` is the receiver audience string.
- `arguments` is a flat object of strings.
- `author_attestation` is the content id of the exact attestation that authenticates `author`. It is never "the current attestation for this key".

### 2.3 attestation/1 profiles in play

| Profile | Issuer (root) | Subject | Window | Binding (exact) | Active-generation evidence (receiver supplies) |
| --- | --- | --- | --- | --- | --- |
| `mac-se-1` (Mac agent) | owner grant root | P-256 | ≤ 366 d, covers every grant naming the key | `{profile:"mac-se-1",mxid,generation}` | `{profile,mxid,generation,active:true}`; mxid filled from the authenticated sender |
| Keymaker v0 agent (Linux agent) | `service_root` (purpose 5) | Ed25519 | ≤ 86 400 s | `{uid,generation,registration_number,master_epoch,owner,path}` | the same six fields plus `active:true`, from protected registry evidence |
| `grant-revocation-1` (publisher) | owner grant root | P-256 | ≤ 366 d | `{profile:"grant-revocation-1",domain:<grant root>}` | n/a |

### 2.4 revocation/1

- Publisher snapshot: body exactly `{complete, entries, issued_at, issuer, type}`, signed by the publisher key.
  - A receiver admits it only when it is at most 60 s old by its trusted clock. Without a fresh snapshot every request refuses; there is no grace period.
- Entries are `{kind,id,from}`.
- Receivers keep a durable, monotonic union of all revocations. A snapshot that drops a known entry is refused as rollback.
- A revocation signed by the owner root wins at any age.
- A revoked publisher fails closed.

## 3. Receiver pipeline (both platforms)

1. Read the event through the a2a projection (§4). The sender is the authenticated a2a sender. Room and event ids must equal the requested ones.
2. `VerifyMessage` (platform verifier) with:
   - the protected facts: audience, the author's attestation by content id, active-generation evidence, a fresh publisher snapshot, the delivery `{room,to,text}` and the trusted time;
   - the author attestation path for the platform of the author key (§2.3).
3. Grant selection:
   - among the pinned grants, take those whose subject equals the author and which cover the action and target;
   - none refuses with `mu-no-applicable-grant`, and more than one refuses with `mu-ambiguous-grant` (interim rule until X8).
4. `Authorize([grant], {key,action,target})`. `Plan.use` gives the policy.
5. Durable accounting before any effect:
   - nonce key = requester key + nonce + audience, held for every request;
   - allowance key = root + grant id + action + target, for `once` only, never refilled;
   - the order is reserve, then intent, then effect, then outcome. An unknown outcome holds and never re-executes.
6. Receiver checks: the account owner for `account.manage`, the room scope for `room.membership`, module pause.

The refusal vocabulary is the platform codes (spec) plus the receiver codes listed in the vectors README.

## 4. Transport: a2a #189

- Send: `a2a post <room> --topic T --envelope @record.json @text`. The text bytes are exactly the ones hashed in `body_sha256`.
- Read: `a2a read <room id> --event <id> --envelope-input --json`.
  - It returns one JSON object plus LF, with exactly nine string fields: `type` (`a2a.event-envelope-input/1`), `sender_mxid`, `receiver_mxid`, `requested_room_id`, `requested_event_id`, `returned_room_id`, `returned_event_id`, `envelope_base64` and `body_text_base64`.
  - Both payloads are unpadded base64url.
- Event key: (room id, event id). The request hash is SHA-256 of the exact envelope bytes.

## 5. Vectors

- Location: `interop/multi-use-grants/` in swarma-keyvault. It contains the published test seeds, one JSON file per case and a README.
- Each case pairs a positive control with negatives that differ in exactly one fact. Fields per case:
  - `id`, `claim`, `positive_control`;
  - `records` (base64url exact bytes);
  - `facts` (the protected context in the platform fixture shape);
  - `event` (sender, room, to, text);
  - `sequence` (for receiver-level cases);
  - `expected` (an exact code per step).
- Families, Mac to Linux and Linux to Mac, with a negative beside each positive:
  - wrong key;
  - wrong scope: action or target;
  - expired grant;
  - revoked grant (publisher snapshot);
  - replay (same event twice);
  - use refill (a `once` grant used again with a new nonce);
  - foreign domain (a grant from another root);
  - stale publisher snapshot (61 s);
  - mismatched body hash;
  - a publisher snapshot that drops an entry (rollback);
  - text at the limit (4096 bytes admitted; 4097 bytes and CR refused);
  - Linux to Mac: a Linux author whose Keymaker attestation has expired while the grant is still valid.
- The check runs on the Mac:
  - every case through the pinned platform verifier;
  - receiver-level cases through the KV receiver.
- L runs the same files through its build. A disagreement is decided against the spec.

## 6. Decisions open for agreement (both sides and the platform owner)

- **D1. Evidence delivery to the Mac receiver for Linux authors.** The Mac receiver needs `service_root`, the Keymaker attestation bytes by content id, the active-generation evidence and the agent revocation snapshots (`agent_revocation_root`).
  - Position: the registry serves them by id (spec §6), and the Mac receiver pins `service_root` and `agent_revocation_root`.
  - Awaiting L's agreement.
- **D2. Publisher snapshots to the Linux receiver.** Decided:
  - the Mac publisher posts each snapshot as an envelope into a dedicated a2a room whose only members are the publisher and the receivers, every **30 s**;
  - the L receiver uses the newest snapshot that is at most 60 s old by its trusted clock, and otherwise refuses;
  - the room, its poster and its members are fixed in the deployment configuration of both receivers, not in this contract.
- **D3. Grants for Linux agents** are issued at an owner sitting on the Mac, with the Linux agent's Ed25519 key id as `subject`.
  - A Keymaker attestation lives at most 86 400 s, so the whole-interval cover rule of §2.1 applies only to `mac-se-1` grantees.
  - For an Ed25519 grantee, the issuer verifies at issuance a current Keymaker attestation of that key and its registry identity (`uid`, `registration_number`). It shows the owner the MXID of that registry identity, and refuses on any mismatch.
  - The receiver then requires a current Keymaker attestation and active-generation evidence for the key on every request (§3, step 2). A request whose attestation has expired refuses, even while the grant is valid.
  - The KV issuer accepts only `mac-se-1` grantees today, so this is a KV change, gated on D1.
- **D4.** The KV receiver currently admits only `mac-se-1` authors. Accepting Linux authors is a KV change, and it is gated on D1.
