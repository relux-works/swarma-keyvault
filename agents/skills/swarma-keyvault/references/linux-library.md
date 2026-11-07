# Linux application-key library composition

Use this route for the existing Ed25519 application-key consumer, distinct from
the Mac-agent multi-use CLI. Read the [application source contract](../../../../docs/linux-application-source.md)
before wiring providers, the [Linux evidence contract](../../../../docs/linux-a2a-key-evidence.md#exact-delta-and-implementation-gate)
for unresolved protected inputs, and the [receiver contract](../../../../docs/linux-receiver.md)
for durable admission and refusal behavior. These are checkout-relative source
links, not bundled installed-skill files. This library supplies no Linux CLI,
transport, protected clock, signing custody or deployed effect provider.

## Explicit provider composition

`NewLinuxApplicationSource(LinuxApplicationBindings{...})` requires all four
functions below. Pass the resulting source as both the evidence and state ports
to `NewLinuxVerifier(policy, source, source, authenticatedEvents)`. Missing
bindings refuse construction; nil and zero-value sources refuse calls. Wiring
checks neither qualify providers nor authorize activation. Source:
[`linux_application_source.go`](../../../../internal/grants/linux_application_source.go).

| Binding | Required protected input and adapter behavior |
| --- | --- |
| `Attestation(contentID)` | Original issuer bytes by exact content ID, with authenticated source/read principal and authorized disclosure. The adapter checks `attestation/1` and the requested ID under the existing parser bound; it neither reserializes nor substitutes a latest-for-key record. |
| `CurrentAgent(key)` | Independent current-generation authority with protected high water, restart recovery and stale/conflict refusal. Each call reads afresh and requires the requested Ed25519 key; the verifier still checks the independently pinned sender, all six binding fields, active state, profile, signature and validity. |
| `Snapshot(root)` | Each pinned signer's original scoped bytes and protected durable monotonic-union continuity. The adapter bounds wire size and preserves availability/rollback flags and old/future observations for verifier/receiver handling. Successful reads or signatures do not establish continuity. |
| `VerificationState(requestHash)` | Qualified time/authority deadline, durable watermark/journal and independent assurance bound to that exact request hash. Flags and nil journal state pass through unchanged; the zero hash keeps its issuance-only meaning and cannot establish A2. |

Returned attestation, snapshot and journal byte slices have detached storage;
providers must not mutate results during a call, including the copy, and must
honor the pinned platform `verifier.Evidence` immutable ownership contract.
No successful evidence is cached between calls. Providers must enforce bounded
authenticated reads and finite deadlines themselves: synchronous ports cannot
interrupt a blocked provider or undo an allocation, and a parser bound is not a
transport bound. Identity evidence does not replace exact-request assurance.

The receiver retains final sampling under its admission lock before reservation
and effect dispatch. Configure its explicit publisher and agent-revocation pins
as specified in the receiver contract; preserve its per-signer durable unions,
refusal observations and UNKNOWN holds. A local clock or same-UID journal is
not protected custody or rollback resistance.

## Requester input and signing boundary

[`SignLinuxRequest`](../../../../internal/grants/linux_requester.go) takes a
`mugrant.RequestSpec` and an explicitly supplied `LinuxRequestSigner`. Text
validation runs first, using the shared byte-exact admissibility rule. Then the
requester requires a live nonnil context, Ed25519 author, exact attestation
content ID, admissible action/target, full room/recipient identities, 16-byte
nonce and UTC whole-second issue time. Lifetime is a positive whole number of
seconds, at most 120. Arguments are limited to 16, with printable nonempty
names up to 64 bytes and valid UTF-8 values up to 512 bytes. Read the source for
the remaining token and target grammar; do not infer permission from syntax.

The local `SignMessage(ctx, key, preimage)` seam signs the **exact platform
preimage**, not its SHA-256 digest, and returns raw 64-byte Ed25519 signature
bytes. The requester verifies that signature before returning canonical
`swarm-envelope/2` `message/1` bytes with the exact text hash. It supplies no key
loader, account credentials or signing provider. Invalid inputs never reach
the signer; a signer error emits no envelope and is not retried. A successful
request does not enroll its attestation or establish current generation: the
receiver authenticates both afresh. Signing examples remain inert without the
separate authorization required by the skill's execution boundary.

## Source behavior controls

Read these existing synthetic tests when checking a proposed composition; run
them only within the task's execution permissions and report actual results
separately from source expectations. No provider or native qualification follows
from an in-process test.

- [`linux_application_source_test.go`](../../../../internal/grants/linux_application_source_test.go):
  `TestLinuxApplicationSourceMissingBindings`, `ExactAttestation` and
  `EvidenceOwnership` (each with the same `TestLinuxApplicationSource` prefix)
  cover absent wiring, exact-ID/oversize/error refusal, detached bytes, fresh
  reads and unchanged flags/request hashes. `TestLinuxApplicationSourceFinalAdmission`
  pairs a valid receiver control with unavailable evidence, identity conflicts,
  inactive/final-generation changes, missing continuity/time/journal and A1-only
  assurance. Refusals leave zero reservations, nonce/allowance holds and effects;
  repairing only the provider admits the identical request once with its journal
  retained.
- [`linux_requester_test.go`](../../../../internal/grants/linux_requester_test.go):
  `TestLinuxTextFirst`, `TestLinuxRequesterPlatformWire` and
  `TestLinuxRequesterRefusesBeforeSigner` cover text precedence, canonical wire,
  verified signatures and input refusal before signing. The `TestLinuxRequesterArgument*`,
  `TestLinuxRequesterCanceledBeforeEntry` and `TestLinuxRequesterSignerErrorNoRetry`
  controls pair boundary/error refusals with valid inputs and verify signer call
  counts; they do not exercise real signing custody.
