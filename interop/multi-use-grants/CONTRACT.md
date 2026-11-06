# Multi-use owner grants: cross-platform interop contract (r8.2, agreed)

Status: r6 revises r3, which both sides agreed. r5 made the contract exact after review; r6 adds the Linux family and the revocation duties. r7, which both sides agreed, states which snapshots count as verified for the revocation duties and adds three vectors. r8 admits an Ed25519 revocation publisher (profile `grant-revocation-2`) and adds the P2 vector family; r8.1 answers the other side's review of r8 (entry points, consumer scope, Linux-author vectors, role distinctness, publisher rotation). r8.2 pins the receiver's refusal precedence (section 3, step 8 before step 9) with one combined vector. Every changed rule is marked "(r5)", "(r6)", "(r7)", "(r8)", "(r8.1)" or "(r8.2)". Both sides agreed r8.1 on 2026-11-05 (UTC), at swarma-keyvault ab045eb3, and r8.2 on 2026-11-06 (UTC).

Owner, 2026-11-05 16:51 MSK: «наши только доверенности под мак довести и чтоб оин со стороны линкуса кросплатформ поддержали - наша отвественность».

Sides:
- **KV (Mac)**: the issuer, Mac requester, Mac receiver and revocation publisher (relux-works/swarma-keyvault);
- **L (Linux)**: the Linux keyvault with Ed25519 agent keys, a Linux requester and a Linux receiver.

## 0. Pins

| What | Pin |
| --- | --- |
| Record format and verifier | relux-works/swarma-envelope `6c71e5226416` (r8; spec `spec/swarm-envelope-2.md`, library `record`, `verifier`) |
| Transport projection | a2a-swarm #189 `25f1e44b002b`, record `a2a.event-envelope-input/1` |
| KV builders | swarma-keyvault `internal/mugrant` |

Anything not stated here follows the pinned spec. Where this text and the spec differ, the spec wins and this text is a defect.

## 1. Roles and algorithms

| Role | Mac | Linux |
| --- | --- | --- |
| Owner grant root (issues grant/1 and the Mac agent and publisher attestations) | P-256, Secure Enclave, user presence (Touch ID) | none; grants for Linux agents are issued on the Mac |
| Revocation publisher (one per grant domain) | P-256, Secure Enclave, no presence (`grant-revocation-1`) | (r8) Ed25519, held by a signing service (`grant-revocation-2`); without one, L consumes the Mac publisher's snapshots |
| Agent (requester) | P-256, Secure Enclave, no presence; attestation profile `mac-se-1` signed by the grant root | **Ed25519**; Keymaker v0 agent attestation signed by the signing-service root (`service_root`, purpose 5) |
| Receiver | swarma-keyvault `grants mu-execute` | L receiver |

Signatures in records are raw: Ed25519 is 64 bytes; P-256 is `r||s` in 64 bytes with low S. DER inside a record is refused. A Mac signer emits DER low-S, and the assembler converts it.

## 2. Records (all `swarm-envelope/2`, envelope members exactly `body,id,signatures,version`)

Domain tags, exactly as `record.Tag` gives them (r5):

| Record | Tag |
| --- | --- |
| grant/1 | `swarma-waggle grant/1` |
| message/1 | `swarma-msg/2` |
| attestation/1 | `swarma-attestation attestation/1` |
| revocation/1 | `swarma-attestation revocation/1` |

- Content id: `sha256:` + hex(SHA-256(tag LF CCJ-1(body))).
- Signing preimage: tag LF CCJ-1({body,key,role,version}) (spec §2.2).
- Each signature is exactly `{key,role,sig}` with role `author`.

### 2.1 grant/1 (multi-use)

- Body members, exactly: `actions, aud, caveats, depth, exp, expires, iat, issuer, min_assurance, nonce, not_before, parent, subject, targets, type`.
- `caveats` is exactly `{expires, lang:"caveats/v2", not_before, use}`, and `use` is `once` or `until_expiry`. (r5) A grant with any vocabulary-v2 action MUST carry `caveats/v2`; without it, the grant refuses with `grant_use_missing` (spec §3.5).
- `depth` is 0 and `parent` is null. `min_assurance` is `{level:"A2",presence:false}`.
- The interval is chosen per grant by the owner, with a hard cap of one calendar year. `iat = not_before`, and `exp = expires`.
- `nonce` is 16 CSPRNG bytes in base64url. `subject` is the agent key id: `p256:` for a Mac agent, `ed25519:` for a Linux agent.
- Vocabulary v2 is a closed allowlist.
  - Actions `work.assign`, `work.require`, `work.contract`, `work.prioritize`, `work.land-order` and `work.accept` apply to kind `product`.
  - `account.manage` applies to `account-scope`, and `room.membership` to `room-scope`.
  - A target id follows the spec grammar: lowercase `a-z`, `0-9` and `-`, optionally qualified once as `qualifier:name`; no `/` and no patterns (spec §3.5). (r6) The KV issuer additionally uses only the `owner:` qualifier, for `account-scope`; this is issuer policy, not a verifier rule.
- Issuer-side binding. These are issuance rules; a receiver cannot observe them (r5, see D3):
  - for a `mac-se-1` grantee, the issuer refuses unless the grantee has a verified attestation under the grant root that covers the whole interval;
  - for an Ed25519 grantee, the whole-interval cover does not apply (a Keymaker attestation lives at most 86 400 s); the issuer applies D3 instead;
  - the issuer refuses unless the publisher attestation for the domain exists and covers the interval;
  - the grantee MXID shown to the owner comes from the verified attestation (`mac-se-1`) or the registry identity (Ed25519).

### 2.2 message/1 (request)

- Body members, exactly: `action, arguments, aud, author, author_attestation, body_sha256, exp, iat, nonce, room, target, to, type`.
- `body_sha256` is the lowercase hex SHA-256 of the exact event text bytes.
- Text rule (r5, byte-exact), ONE rule for both sides. The text is admitted only when all of these hold:
  - it is at most **4096 bytes**;
  - it is valid UTF-8;
  - it is not blank: after removing leading and trailing Unicode White_Space (Go `strings.TrimSpace`), something remains;
  - it contains no rune for which Go `unicode.IsControl` is true, except LF (U+000A) and TAB (U+0009). This refuses CR, the other C0 controls, DEL and the C1 controls;
  - it contains no U+FFFD;
  - it contains none of the bidi controls U+061C, U+200E, U+200F, U+202A to U+202E, or U+2066 to U+2069.
- The requester refuses to sign text outside the rule. The receiver refuses it with `mu-request-text-refused` at the point given in §3, even when `body_sha256` binds it.
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
| (r8) `grant-revocation-2` (publisher) | owner grant root | Ed25519 | ≤ 366 d | `{profile:"grant-revocation-2",domain:<grant root>}` | n/a |

(r8) Publisher profiles.
- A receiver pins exactly one publisher: its key and its attestation. The profile fixes the algorithm: `grant-revocation-1` with a P-256 key, `grant-revocation-2` with an Ed25519 key. Any other pair, or an unknown profile, refuses; no profile is inferred from the key.
- Only the owner grant root appoints a publisher. An attestation issued or signed by any other key, such as a signing-service root, is refused. The owner signs it under Touch ID at a sitting (`mu-issue --kind publisher` or `publisher-ed25519`). A signing service may hold an Ed25519 publisher key but cannot appoint one.
- The publisher key differs from each of these six roles: the grant root, the operator root, `service_root.key`, `agent_revocation_root.key`, the commit-signing key and the enrollment publisher (the platform spec checks this list). For a Mac author no service or registry root is pinned, so for that receiver the distinctness is a provisioning duty.
- Entry points and codes. A receiver that passes the pinned publisher to the platform on each request returns these codes:
  - for a Mac author, `key_binding_invalid` from `VerifyMessage`, because the platform resolves the publisher during agent-attestation intake;
  - for a Linux author, `revocation_invalid`, because Authorize resolves the publisher and its G7 gate maps the binding refusal.

  A receiver that validates the pinned publisher attestation when it loads its configuration meets the vectors with an invalid publisher attestation by refusing that configuration, before any request or effect. That refusal counts as the expected verdict for those steps. A rig must not translate one entry point's refusal into the other's code.
- (r8.1) Consumer scope. A receiver implements r8 only when it pins a platform verifier with profile 2 (§0) and its own publisher gate admits the profile the verified attestation declares. A receiver that does not fails closed on every profile-2 input. r8 qualifies no such receiver.
- (r8.1) Rotation. Pinning a different publisher on an existing journal is not defined by this contract. It is blocked until the receiver re-initialises under a new state epoch and re-applies the owner-root revocations, as the restore rule in §2.4 requires. The KV receiver enforces this: it pins its snapshot signers and refuses, before any state change, a journal that holds a union or mark from any other signer (the owner root aside).
- Everything in §2.4 applies to both profiles. Custody of an Ed25519 publisher key is a deployment qualification, outside this contract.

### 2.4 revocation/1

- A publisher snapshot has a body of exactly `{complete, entries, issued_at, issuer, type}` and is signed by the publisher key. (r6) Its constraints:
  - `complete` is `true`;
  - `entries` are unique and sorted by `kind`, then `id`;
  - `kind` is `record` or `key`;
  - `from` is an exact UTC time no later than `issued_at`.
- (r6) Carriage: the Mac receiver reads the newest snapshot the publisher job writes to an owner-private file. The L receiver reads the newest snapshot posted to the dedicated room (D2). When no snapshot can be read, the request refuses with `revocation_unavailable`.
- Freshness (r5):
  - age = trusted receiver now − `issued_at`;
  - a snapshot is admitted only when `issued_at` is not in the future and the age is at most 60 s, inclusive;
  - without such a snapshot every request refuses; there is no grace period.
- Entries are `{kind,id,from}`.
- (r6) Every snapshot a receiver verifies for an event is recorded before the request is judged, whatever the outcome. Its entries join a durable, monotonic union kept per signer: the publisher, and for a Linux author the agent revocation root. Its `issued_at` raises that signer's high-water mark only when it is not in the future by the trusted clock, the same test freshness applies; the entries of a future-dated snapshot still join the union, but the snapshot cannot lock out later correct ones. A snapshot that refuses a request as `revoked` is therefore remembered. A later snapshot without the entry, whether older or with the same `issued_at`, cannot let the grant or key act (`mu-grant-revoked`).
- A snapshot that drops an entry its own signer published before is refused as rollback.
- (r7) A verified snapshot is one signed by its pinned signer, at most 8192 bytes as signed (the platform verifier's evidence bound), whose body also has the static shape the platform verifier enforces before it judges age or entries:
  - exactly the members `complete`, `entries`, `issued_at`, `issuer` and `type`;
  - `complete` is `true`, and `issued_at` is an exact UTC time;
  - each entry has exactly `kind`, `id` and `from`, where `kind` is `key` (with a valid key id) or `record` (with a content id) and `from` is an exact UTC time.

  A signed snapshot over that size or without that shape refuses the request it accompanies and is not recorded: its entries do not join the union, and its `issued_at` raises no mark. The sorting and `from <= issued_at` constraints above are publisher obligations; the pinned verifier does not enforce them, so they do not decide whether a snapshot is recorded.
- (r6) Revocation entries recorded before per-signer unions existed carry no signer: they still revoke, but they are never compared for rollback.
- `issued_at` is the per-signer sequence of snapshots (no extra member). Each receiver keeps, durably, the newest `issued_at` it has accepted per signer. A snapshot older than that refuses as rollback with `mu-revocation-snapshot-rollback`, even when it is fresh and drops nothing; an equal `issued_at` is admitted.
- A receiver restored from a backup re-initialises its journal under a new state epoch and re-applies the owner-root revocations before it admits any request. A restored journal can lack revocations, and no local mark detects that.
- A revocation signed by the owner root wins at any age. (r6) Owner-root entries form their own set, apart from every signer's union. A publisher is not required to mirror them, and a publisher snapshot without them is not a rollback. Owner-root revocations reach each receiver out of band, into its protected configuration; they never pass through the publisher, so a publisher that keeps signing fresh snapshots without an entry cannot hide one. The issuer prepares them with `mu-root-revocation-prepare`, and the owner signs them under Touch ID.
- A revoked publisher fails closed.

## 3. Receiver pipeline (both platforms, in this order) (r5)

1. Read the event through the a2a projection (§4). The sender is the authenticated a2a sender. Room and event ids must equal the requested ones; otherwise refuse with `mu-envelope-projection-refused`.
2. Look up the sender's registry identity. No identity refuses with `mu-sender-not-attested`.
3. Apply the text rule (§2.2) to the delivered text. A violation refuses with `mu-request-text-refused`.
4. Load the newest publisher snapshot. A Linux author also needs its registry evidence (D1).
5. Call `VerifyMessage` (platform verifier) with the protected facts in §5.1. Any refusal returns the platform code.
6. Select the grant: among the pinned grants, take those whose subject equals the author and which list the action and the exact target kind and id, regardless of their validity (r5). None refuses with `mu-no-applicable-grant`; more than one refuses with `mu-ambiguous-grant`. This is an interim rule. Selection is structural, so an expired grant pinned beside its renewal is ambiguous; unpin the old one.
7. Call `Authorize([grant], {key,action,target})`. `Plan.use` gives the policy.
8. Receiver checks:
   - audience and grant root equal the binding (`mu-audience-mismatch`);
   - the request has not expired;
   - the grant is not locally paused (`mu-grant-locally-paused`);
   - the action is not grant authority (`mu-request-widens-authority`);
   - the target is in owner scope (`mu-request-out-of-owner-scope`). (r6) The argument keys are:
     - `product` actions: `module`, which must be one of the receiver's modules (`work.assign` also carries `title`);
     - `account.manage`: `account`, an MXID that the registry maps to the receiver's owner;
     - `room.membership`: the target id must equal the receiver's room scope; `room` must be a non-empty room id, and `account` an MXID the registry maps to the receiver's owner.
9. Under the journal lock, re-run steps 2 to 8 (the receiver repeats the whole check), then apply the revocation duties of §2.4 (`mu-grant-revoked`, `mu-revocation-snapshot-rollback`).
10. Durable accounting before any effect:
    - nonce key = requester key + nonce + audience, held for every request (`mu-request-nonce-already-held`);
    - allowance key = root + grant id + action + target, for `once` only, never refilled (`mu-grant-use-already-held`);
    - the order is reserve, then intent, then effect, then outcome. An unknown outcome holds and never re-executes (`mu-dispatch-outcome-unknown-use-held`).

### 3.1 Refusal vocabulary (r5)

Platform codes are returned unchanged from the pinned verifier. (r6) Among them, the vectors include these; any other platform code is possible and means what the spec says:

| Code | Meaning in the vectors |
| --- | --- |
| `envelope_signature_invalid` | the request signature does not verify under the author key |
| `envelope_malformed` | the request breaks a structural rule, for example `exp - iat` over 120 s |
| `audience_mismatch` | the request names another audience |
| `message_room_mismatch` | the request names another room than the delivering room |
| `message_recipient_mismatch` | the request is addressed to another recipient |
| `expired` | the grant interval has ended |
| `revoked` | a fresh snapshot revokes the grant or the agent key |
| `key_binding_unavailable` | required evidence is missing or stale: no binding for the grant issuer, attestation not served, snapshot over 60 s |
| `key_binding_invalid` | evidence does not match: an expired Keymaker attestation, a generation that moved, or a Linux identity whose referenced attestation is a `mac-se-1` attestation by the grant root instead of a Keymaker one |
| `revocation_unavailable` | no revocation snapshot could be read (r6) |
| `message_text_mismatch` | the delivered text does not hash to `body_sha256` |

Receiver codes:

| Code | Meaning |
| --- | --- |
| `mu-envelope-projection-refused` | the projection record is not exactly the a2a #189 record |
| `mu-sender-not-attested` | the sender has no registry identity, or the author is not its key |
| `mu-request-text-refused` | the text breaks the §2.2 rule |
| `mu-no-applicable-grant` / `mu-ambiguous-grant` | grant selection found none, or more than one |
| `mu-audience-mismatch` | the audience or grant root differs from the receiver binding |
| `mu-grant-locally-paused` | the receiver paused this grant |
| `mu-request-widens-authority` | the action would issue, widen or delegate authority |
| `mu-request-out-of-owner-scope` | the target is outside the owner's scope |
| `mu-grant-revoked` | the durable union or an owner-root revocation revokes it |
| `mu-revocation-snapshot-rollback` | the snapshot drops a known entry |
| `mu-request-nonce-already-held` | replay |
| `mu-grant-use-already-held` | a `once` grant already used |
| `mu-required-state-unavailable` | the journal or required evidence is unavailable |
| `mu-effect-refused` | no effect is registered for the action; refused before any reservation (r6) |
| `mu-receiver-config-refused` | the receiver configuration is not admitted (r6) |
| `mu-dispatch-outcome-unknown-use-held` | the effect outcome is unknown; the use stays held |

## 4. Transport: a2a #189

- Send: `a2a post <room> --topic T --envelope @record.json @text`. The text bytes are exactly the ones hashed in `body_sha256`.
- Read: `a2a read <room id> --event <id> --envelope-input --json`.
  - It returns one JSON object plus LF. (r5) The object has exactly nine members with no duplicates, all strings: `type` (`a2a.event-envelope-input/1`), `sender_mxid`, `receiver_mxid`, `requested_room_id`, `requested_event_id`, `returned_room_id`, `returned_event_id`, `envelope_base64` and `body_text_base64`.
  - Both payloads are canonical unpadded base64url: padding, other alphabets and non-zero trailing bits refuse (r6). The envelope is 1 to 65 536 bytes and the text 1 to 32 768 bytes after decoding (the §2.2 rule then applies its 4096-byte limit). Anything else refuses with `mu-envelope-projection-refused`.
- Event key: (room id, event id). The request hash is SHA-256 of the exact envelope bytes.

## 5. Vectors

- Location: `interop/multi-use-grants/` in swarma-keyvault. It holds `keys.json` (published test seeds), `cases/` (one JSON file per case) and a README.
- Case file format (r5), exactly the members the files carry:
  - `format`: `swarma-keyvault/mu-interop-case/1`;
  - `id`, `claim`, and `positive_control` for a negative;
  - `pins`: `grant_root`, `audience`, `publisher_key`, `room`, `receiver_mxid`, `sender_mxid`, `agent_key`, `agent_generation`, `owner`, `room_scope`, `modules`, `registry_owners`;
  - `records`: `grants`, `agent_attestation`, `publisher_attestation`, as unpadded base64url of the exact bytes;
  - `events`: each with `event_id`, `envelope`, and `text` (base64url of the exact text bytes);
  - `steps`, run in order against one fresh receiver journal. Each has `event`, a trusted `now`, the publisher `snapshot` current at that time, and `expected`, the exact verdict: `succeeded` or a refusal code from §3.1.
- Every negative differs from its positive control in one fact.
- (r8.2) `M-N-out-of-scope-and-revoked` deliberately combines two failures to pin refusal precedence; it is an explicit exception to the one-fact rule.
- The check runs on the Mac: every step goes through the pinned platform verifier and the KV receiver. L runs the same files through its build. A disagreement is decided against the spec.

### 5.1 Pins to verifier facts (r5)

For a Mac author, the receiver gives `VerifyMessage` and `Authorize` exactly these protected facts (KV: `internal/grants/mu_platform.go`):

| Fact | Value |
| --- | --- |
| `audience` | `pins.audience` |
| `required_roles` | `["author"]` |
| `known_keys` | `[author key]` |
| `root` | `pins.grant_root` |
| `attestations` | `{<author_attestation id>: <attestation bytes>}` |
| `agent_attestation_ids` | `{<author key>: <author_attestation id>}` |
| `active_generations` | `{<author key>: {profile:"mac-se-1", mxid:<authenticated sender>, generation:pins.agent_generation, active:true}}` |
| `revocations` | `{pins.publisher_key: {availability:"available", max_age:60, rollback_safe:true, snapshot:<step snapshot>}}` |
| grant revocation publisher | `records.publisher_attestation` |
| `time` | `{trusted:true, fresh:true, authority_until: now + 300 s}` |
| `now`, `watermark` | the step's `now` |
| `watermark_available`, `id_journal_available`, `replay_available` | `true` |
| `seen`, `used_actions` | empty |
| `assurance` | `{level:"A2", presence:false}` |
| `operator_attestations` | `{}` (explicitly empty) |
| `delivery` | `{room: pins.room, to: pins.receiver_mxid, text: <event text>}` |

The Linux additions to this table follow D1 (the registry evidence).

## 6. Decisions

- **D1. Evidence delivery to the Mac receiver for Linux authors.** Agreed:
  - the registry serves Keymaker attestation bytes by content id, the active-generation evidence and the agent revocation snapshots;
  - the Mac receiver pins `service_root` and `agent_revocation_root`.
- **D2. Publisher snapshots to the Linux receiver.** Agreed:
  - the Mac publisher posts each snapshot as an envelope into a dedicated a2a room whose only members are the publisher and the receivers, every **30 s**;
  - the L receiver applies the §2.4 freshness rule to the newest snapshot it holds;
  - the room, its poster and its members are fixed in the deployment configuration, not in this contract.
- **D3. Grants for Linux agents.** Agreed. They are issued at an owner sitting on the Mac, with the Linux agent's Ed25519 key id as `subject`.
  - At issuance, the issuer verifies a current Keymaker attestation of that key and its registry identity (`uid`, `registration_number`). It shows the owner the MXID of that identity, and refuses on any mismatch.
  - (r5) This binding is an issuance property; a receiver cannot check it later.
  - What the receiver enforces on every request is a current Keymaker attestation, the active-generation evidence and the registry identity of the sender. A request whose attestation has expired refuses, even while the grant is valid.
- **D4. Linux authors at the Mac receiver.** Agreed; implemented as a KV change after D1.
