# Linux application-key evidence: first source unit

Status: proposed implementation delta against the agreed multi-use contract;
no new wire format, trust root, transport, custody adapter or activation.

The first Linux identity is an Ed25519 application signing key. A Matrix display
name proves nothing. The authenticated sender MXID is an index into protected
registry policy; neither that address nor a registry response appoints a trust
root. General MXID enrollment/authority and arbitrary-identity grants are later
stages. The existing sender-index check below remains mandatory for this
contract's delivered requests.

## Exact source baseline

| Component | Revision | Relevant source |
| --- | --- | --- |
| Grant consumer and agreed contract | `a538e277d66ff7d32c41e19740a555047c11f122` | `interop/multi-use-grants/CONTRACT.md` r8.2, §§2.1–2.4, 3, 5.1, D1–D4; `internal/grants/linux_verifier.go`, `linux_requester.go`, `linux_receiver.go`; `internal/mugrant/keymaker.go` |
| Envelope dependency actually used by that consumer | `6c71e52264166495f64d62ce34d68b492c736140` | `spec/swarm-envelope-2.md` §§2.2–2.6, 3.5, 6; `record`, `verifier`; module version `v0.0.0-20261105191315-6c71e5226416` |
| Keymaker public source | `bfb3eded0d3e1e8c7935f69666326f1a79b8faae` | `internal/keymaker/message_attestation.go`; `internal/enrollment/README.md`; `spec/keymaker.md` |
| Owner-registry public source | `d907cff96ea976250e410bb63e84edb1baed2290` | `design/owner-registry.md` §§2–5; `internal/intake`, `internal/store`, `internal/composition` |

The latter two are public interface observations, not new dependency pins.
Their module dependencies differ from the consumer's; no upgrade or cross-module
replacement is part of this unit. Existing C01 analysis is contract input; the
agreed r8.2 contract and its pinned platform spec govern. Historical G/G2 local
certificates remain incompatible inputs and are never relabeled `grant/1`.

## Authority and public enrollment

There are separate authorities, not a new certificate chain:

1. Protected installation policy pins the owner's grant root. That root signs
   `grant/1` and the appointed publisher's `attestation/1`. Only the owner can
   appoint that publisher; a service root or registry signature cannot do so.
2. Protected policy separately pins `service_root` with integer purpose 5.
   This root authenticates the Linux agent's `attestation/1`; the subject cannot
   appoint itself or become a grant root. The owner-registry stores original
   signed content; its storage or commit signature does not replace the issuer.
3. The Linux subject is exactly `ed25519:` plus canonical unpadded base64url of
   the 32 public bytes. Its attestation body is exactly:
   `type,issuer,subject,key_class,purpose,roles,actions,iat,exp,binding`.
   `subject` is `{algorithm:"Ed25519",key_id,public_bytes}`; `key_class` is
   `agent`, `purpose` is `swarma-msg`, `roles` is `["author"]`, and `actions`
   is `["message.sign"]`. These authenticate provenance, not grant authority.
4. `binding` is exactly `{uid,generation,registration_number,master_epoch,owner,path}`.
   UID is an integer in 0..4294967294, registration number in
   1..9007199254740991; the four strings are nonempty UTF-8 of at most 255 bytes,
   compared without normalization. Independently typed protected generation
   evidence has those six fields plus `active:true` and must match all six.
   A reused UID alone is insufficient.
5. Registrar `registration/1` and offline-publisher-signed `enrollment/1` remain
   their own records and domains. Keymaker's existing enrollment authority uses
   an approved Git revision/object format, maintainer allowlist, separate
   publisher pin, audience, station classification, generation narrowing and
   reconciled high water. `Authority.Authorize` returns an `EnrolledKey` for
   its purpose-2 registration path; it does **not** return the purpose-4 message
   identity or satisfy the grant consumer's current-generation evidence port.
   Do not reinterpret an enrollment record, public key lookup or commit as an
   agent attestation. Registrar's pinned v0 envelope is exactly `{body,id,sig}`,
   with domain `swarma-registrar registration/1` or
   `swarma-registrar enrollment/1`; its preimage is domain LF CCJ-1(body).
   It is not a `swarm-envelope/2` record. Registration's seven body members
   are `type,key,name,aud,nonce,iat,exp`: the enrolled host key proves
   possession for that audience/name, with a 16-byte nonce and at most
   120-second lifetime. Enrollment's body is `type,host,keys,names,seq,state`
   plus `uid_map` when required for a station. The separately signed,
   operator-approved commit and offline enrollment signature must both verify;
   retained sequence/tombstone history prevents rollback. Possession of the
   registration host key proves neither the Linux agent author key nor grant
   authority. This unit defines no self-enrollment endpoint.

All present key roles must retain the platform's separation. The consumer
constructor checks distinct grant root, purpose-5 root, agent revocation root
and publisher, and verifies the publisher appointment. Globally configured
operator, commit-signing and enrollment-publisher roles retain their separate
provisioning obligations; the four-pin constructor alone does not prove them.

## Existing interfaces to reuse

These are existing Go ports in `internal/grants/linux_verifier.go`, not a new
service API:

```go
type LinuxEvidenceSource interface {
    Attestation(contentID string) ([]byte, error)
    CurrentAgent(key string) (LinuxRegistryAgent, error)
    Snapshot(root string) (LinuxSnapshot, error)
}
type LinuxStateSource interface {
    VerificationState(requestHash [32]byte) (LinuxVerificationState, error)
}
```

`LinuxRegistryAgent` carries `Key, MXID`, integer `UID, RegistrationNumber`,
`Generation, MasterEpoch, Owner, Path`, and boolean `Active`. Protected
`LinuxVerifierConfig.LinuxAgents` independently pins sender MXID to
`MULinuxAgent{Key, UID, RegistrationNumber}`. A response cannot supply its own
identity pin. `CurrentAgent` is refreshed per invocation; it must independently
match that pin, the authenticated sender and the exact signed attestation.
`Attestation` must serve the exact signed `author_attestation` content ID; no
fallback to the latest attestation for the same key is permitted.

`LinuxSnapshot` contains exact `Wire` bytes and `Available, RollbackSafe`.
A signature alone does not establish rollback safety. The receiver needs both
the appointed grant publisher's and agent revocation root's snapshots for a
Linux author. `LinuxVerificationState` supplies qualified time, authority-until,
watermark and availability, ID-journal bytes and availability, and independent
request-bound `Assurance`. A current agent attestation gives A1 origin; it must
never synthesize the contract's A2 session evidence. The all-zero request hash
is reserved by the existing issuer-side identity check.

Existing issuer entry point:

```go
func (p *LinuxVerifier) AdmitLinuxGrantee(
    key, reference, mxid string, uid, registrationNumber int64,
    now time.Time,
) (LinuxRegistryAgent, error)
```

It verifies current exact Keymaker identity, generation and scoped revocation
at issuance. It does not sign, enroll, prove future attestation coverage, or
establish owner presence. `mugrant.BuildGrant` additionally checks the
publisher's interval cover and the chosen key/registry identity. The Mac issuer
owns rendering, owner presence and final grant signature. The grant's subject
is the Ed25519 key, not the display name or MXID.

## Required verification predicates

| Boundary | Acceptance predicate | Paired refusal |
| --- | --- | --- |
| Exact envelope | Existing four-member `swarm-envelope/2`; CCJ-1, content ID and signature over the platform domain/preimage | Tamper, wrong key/root, changed content ID or incompatible profile refuses |
| Linux identity | Purpose-5 signature, exact public bytes and six-field current active binding | Wrong UID/registration/generation/epoch/owner/path, inactive generation or absent evidence refuses |
| Attestation time | Start inclusive, end exclusive; positive window at most 86400 seconds; current at issuance and every request | 86401-second window, future or expired attestation refuses even if grant remains valid |
| Request | `author` is the attested key; exact `author_attestation`; exact delivery room/recipient/text hash; whole-second lifetime at most 120 seconds | Different sender key/reference, body text, room, recipient or overlong lifetime refuses |
| Grant | Exact pinned owner root, audience, subject key, closed action and exact target; depth 0/parent null; owner interval at most one calendar year | Foreign root, audience, grantee, action/target, expired grant or widening authority refuses |
| Assurance/time | Independent exact-request A2 evidence and qualified current time/watermark/journal | A1 identity alone, missing assurance, stale/untrusted clock or unavailable journal refuses |
| Revocation | Required snapshots no later than trusted now and at most 60 seconds old; original scoped signatures, continuity and owner-root overrides | 61-second/future/unavailable snapshot, revoked key/grant/publisher, rollback or dropped entry refuses |
| Use | Signed `caveats/v2.use` is `once` or `until_expiry`; durable nonce key is author+nonce+audience under both | Reused nonce refuses under both; `once` cannot refill with a new nonce |
| Effect | Serialized final identity/time/revocation/scope recheck; reserve → intent → effect → outcome | Missing state/effect or unknown outcome refuses/retains holds; no automatic retry |

Unknown outcomes retain their holds. Platform
refusal codes pass through; receiver codes and precedence remain those of r8.2.
No new diagnostic is introduced by this table. The durable receiver, not a
`LinuxVerifier` candidate, owns replay, allowance and effect admission.

## Exact delta and implementation gate

The missing unit is a protected **evidence adapter for the existing ports**,
not another Linux signer or format. D1 specifies what must be supplied, but it
does not define an authenticated read transport or a qualified publication and
active-generation provider:

- Keymaker's `messageIssuer` is internal, has no daemon constructor or
  root-signing RPC, and explicitly leaves publication/activation absent. Its
  qualified-time projection/provider-latency gate remains stated in source.
- The owner-registry has intake, storage, publication records and process-local
  composition. Its design explicitly separates content approval, source landing,
  consumer integration, serving/disclosure and activation. Those are not proof
  of an available grant-consumer evidence provider.
- The Linux grant module supplies in-process ports and synthetic fixtures; its
  documentation explicitly supplies no live transport, clock/session provider,
  signing-service custody or effect provider.

Before implementing that adapter, its custodians must bind one exact candidate
contract to: (a) the authenticated read principal and disclosure scope; (b) the
by-content-ID source with original-byte preservation and bounded reads; (c) the
independent active-generation/currentness source and continuity evidence;
(d) the scoped snapshot source and rollback/recovery policy; (e) the existing
qualified time and exact-request assurance provider; (f) deadlines, unavailable
behavior and final serialized recheck. Do not fill these with endpoint guesses,
TOFU, event-provided pins, cached generation forever, or synthetic A2 facts.

Accountable next hops are the Keymaker custodian for original attestation
publication/current binding, owner-registry custodian for D1 read/disclosure and
continuity, and grant consumer custodian for port integration/final admission.
The shared architects review their one bounded adapter contract before build.
This assigns technical responsibility, not a new repository or landing grant.

The first implementable follow-up is one adapter behind `LinuxEvidenceSource`,
with no changes to `record`, key derivation, grant schema or the canonical
interop corpus. Acceptance must pair the valid control with each refusal above,
exercise unavailable/stale/conflicting evidence and final-check generation
changes, and demonstrate zero reservations/effects on refusal. A separate
review must bind the exact candidate head/tree. Native Mac verification,
protected deployment/custody and live cross-host acceptance remain external
criteria; an offline synthetic run cannot satisfy them.

## Existing controls to run before that follow-up

Use the consumer's unchanged pinned dependencies and synthetic tests:

- `TestKeymakerAttestation`, `TestGrantLinuxGrantee`: public-key binding,
  issuance-time checks and the exact 86400-second boundary.
- `TestLinuxVerifierCurrentKeymakerLongGrant`,
  `TestLinuxVerifierRegistryAdmission`, `TestLinuxVerifierIssuanceGate`,
  `TestLinuxVerifierExactConcurrentAttestations`: key-first identity, refreshed
  generation and exact by-ID lookup, with refusal controls.
- `TestLinuxVerifierProtectedClockAndSnapshots`,
  `TestLinuxVerifierGrantAndEnvelopeRefusals`: assurance, audience, scope,
  validity, signatures and freshness.
- `TestLinuxRequesterPlatformWire`, `TestLinuxRequesterRefusesBeforeSigner`,
  `TestLinuxTextFirst`: the existing request format and pre-sign refusals.
- `TestLinuxInteropVectors`: the canonical 89-case/109-step corpus through
  the verifier and durable receiver, including nonce replay and use accounting.

These controls establish source behavior only. They neither qualify an adapter
that does not exist nor authorize real enrollment, signing, grants or effects.
