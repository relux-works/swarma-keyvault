# Linux application-key consumer composition

`LinuxApplicationSource` implements the existing `LinuxEvidenceSource` and
`LinuxStateSource` ports for the first Ed25519 application-key consumer. It is a
source composition unit. Protected provider integration and activation remain
unqualified. The agreed r8.2 contract, pinned envelope dependency and canonical
interop corpus continue to govern.

The installation supplies all four `LinuxApplicationBindings` functions. Their
signatures match the existing ports exactly. Missing bindings refuse
construction; a nil or zero-value source refuses every call. There are no
endpoints, credentials, default clock, signer or evidence fallback in this unit.

```go
source, err := NewLinuxApplicationSource(LinuxApplicationBindings{
    Attestation:       protectedEvidence.Attestation,
    CurrentAgent:      protectedEvidence.CurrentAgent,
    Snapshot:          protectedEvidence.Snapshot,
    VerificationState: protectedState.VerificationState,
})
// Handle err before constructing the verifier. All provider bindings above
// are required protected installation inputs, not request-derived values.
verifier, err := NewLinuxVerifier(policy, source, source, authenticatedEvents)
```

`Attestation` reads only the requested content ID and checks its exact type and
content ID with the existing parser. It returns original bytes without
reserialization. It never substitutes a newer attestation for the same key.
`CurrentAgent` reads afresh each time and requires the requested Ed25519 key.
The existing verifier still compares the independently pinned sender identity,
all six signed binding fields, active state, profile, signature and validity.

Snapshot wire uses the existing envelope byte bound. Availability and rollback
safety pass through unchanged; a successful read cannot establish either.
Old/future signed observations are left to the verifier and durable receiver,
which retain authenticated observations on refusal under the agreed rules.
Qualified time, availability flags, journal presence and exact-request assurance
also pass through unchanged. The zero request hash retains its existing
issuance-only meaning. Identity evidence supplies no substitute A2 assurance.

Returned attestation, snapshot and journal byte slices are copied. Providers
must not mutate their returned data during a call, including the adapter's
copy. Providers must also respect the immutable evidence ownership contract of
the pinned platform's `verifier.Evidence` type. No successful result is cached
between calls. Final sampling remains inside the existing receiver admission
lock, before nonce reservation and effect dispatch.

## Required protected provider bindings

This source unit does not resolve the following clauses of the existing
[Linux evidence contract](linux-a2a-key-evidence.md#exact-delta-and-implementation-gate):

| Required input | Provider obligation still to bind |
| --- | --- |
| Original attestation | By-content-ID source/revision, authenticated server and read principal, authorized disclosure, original issuer bytes, bounded response/error handling and finite read deadline |
| Current agent | Independent current-generation authority, protected revision/high water, restart recovery and stale/conflict refusal |
| Required snapshots | Each pinned signer's original scoped bytes, durable monotonic-union continuity, rollback/recovery custody and bounded reads |
| Verification state | Qualified time/authority-until, durable watermark/journal and independent assurance for the exact request hash, with finite operation deadlines |

The synchronous existing ports do not expose transport cancellation or read
limits. Actual providers must enforce admitted bounds and deadlines before
returning; this composition cannot interrupt a blocked function or undo its
allocation. The existing envelope parser bound is a consumer bound, not proof
of a complete transport limit. No response flag qualifies continuity or custody.
These unresolved inputs remain explicit functions; construction checks wiring
only. Independent exact-source review, protected deployment and native
qualification remain separate requirements.

General MXID enrollment, human cross-signing and arbitrary-identity grants are
later elements. The existing protected sender mapping and all first-run
currentness, continuity, qualified-time, assurance and final-admission checks
remain required.

## Offline causal controls

`TestLinuxApplicationSource*` uses explicit synthetic in-process providers,
ephemeral test records and countereffects. It pairs a valid control with missing
bindings, exact-ID failures, oversized envelopes, unavailable evidence, identity
conflicts, inactive state, unavailable continuity/time/journal, A1-only assurance
and a generation change at the second receiver sample. Refusals assert zero
reservations, nonce holds, allowance holds and effects; repairing only the
provider admits the identical request once using the same receiver journal.
These tests establish source behavior, not native custody or live admission.
