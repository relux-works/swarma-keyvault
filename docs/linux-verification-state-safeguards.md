# Verification state safeguards

Status: partial consumer safeguards, not a consent provider. Protected reads
remain disabled: this change supplies no read admission, principal, transport,
installed trust root, qualified clock, native custody or deployment binding.
It does not establish readiness for protected effects.

The contract's API baseline is commit
`af3010961ad85bc9ad121bf6d6f998e50899d4d9`. The implementation base is
`d9e5b2143f2cf1808558231b10b34c2dc0731390`; the intervening change adds requester
callback controls only. Those tests and the repository skill are preserved.
The existing `VerificationState([32]byte) (LinuxVerificationState, error)` port,
`grant/1`, `swarm-envelope/2`, dependency versions and journal formats are
unchanged. A later source change requires another independent exact-revision
review; these historical pins are not a claim to implement at the older tree.

## Implemented restrictions

Issuance accepts a `use:"once"` spec only when it has one entry. Existing entry
validation then produces exactly one action and one target. Both verifier
adapters also refuse an otherwise authorized once grant unless its signed
arrays contain exactly one action and one target. This check follows the
pinned verifier's existing ordered checks, preserving its signature, interval,
revocation and assurance refusals. The additional accounting refusal uses the
existing `ErrMUState`; no wire error grammar is introduced. Until-expiry scope
and existing malformed-input checks remain unchanged.

This restriction makes the existing per-right `muAllowanceKey` cover the whole
once grant. There is no new grant-wide counter or authority journal. The
receiver still owns final verification and durable reserve, intent, effect and
outcome ordering. A failed or lost effect reply retains UNKNOWN and the
consumed once allowance. A new request nonce does not refill it.

Before copying an ID journal, the application source and verifier reject more
than 4,096 bindings, an individual wire value above the existing 65,536-byte
envelope limit, or a journal above the pinned Evidence 1 MiB content budget
(including its map/key/value overhead). They return no partial history and
evict nothing. An over-limit state is unavailable, following the existing
state-source failure path (`time_unavailable` at verifier entry). Other
availability flags, nil versus empty history and qualified instants are not
repaired or fabricated.

These are journal consumer limits, **not** enforcement of the complete
projected-view budget, record/read count or provider deadlines. A synchronous
callback can already have allocated or blocked before returning. A wrapper or
successful constructor cannot qualify that source.

## Authority remains separate

The accepted trust anchor is the existing installed `GrantRoot`, pinned to the
owner's grants-key SPKI through a reviewed custodian installation. This change
does not install one or attest that any such installation has occurred. No
Matrix-master or one-year root-grant chain is implemented or claimed. An MXID
remains an index to independently pinned identity.

Grant scope is checked by the existing `Authorize`. A grant is not evidence
that a human consented to an exact future agent request. No A2 is derived from
it, and an A2-required grant refuses with `grant_assurance_insufficient` under
A1 evidence. Missing assurance retains `grant_assurance_unavailable`; asserted
A3 is not admitted. The issuer's existing signed A2 minimum is not silently
lowered. The lab's signed A1-minimum records exercise the existing platform
grant-scope path, not a new issuer option or a production consent ceremony.

## Remaining implementation slice

A real provider still needs a complete immutable local view staged through
bounded protected source implementations, with update exclusion spanning the
final verification and the existing durable admission transaction. It must
enforce the accepted ceilings: 1 MiB complete view, 128 records/read operations,
4,096 retained ID bindings, 2 seconds staging, 100 milliseconds complete final
local recheck/reservation and 1,024 bytes of private diagnostic status. An
original qualified authority/evidence expiry is always an earlier deadline;
retries cannot extend it. No bound is widened here.

Time/watermark/exact-ID plan commitment must be reconciled atomically with the
existing MU journal. The current decision projection does not commit the
pinned verifier's complete time/ID plan. A second authority journal, a timed-out
goroutine around an uncancellable callback, or an empty-history default would
not resolve that requirement. Until the implementation and independent review
establish these properties, the provider stays disabled. Rollback must retain
all consumed uses, nonces, revocation unions, watermarks, exact ID bytes and
unknown outcomes; it cannot restore availability by deleting safety history.

## Offline evidence

`TestGrantOnceSingleRight` checks issuance beside valid until-expiry controls.
`TestLinuxContractOnceScope` and `TestMUPlatformOnceScope` exercise the real
verifiers and receivers with ephemeral lab signatures, including malformed and
multiple rights. The Linux contract controls also cover grant-scope admission,
A2 refusal, inclusive/exclusive interval behavior, concurrent once consumption,
unknown effects, final invalidations, retained revocations and state caps.
Existing application-source, requester, admission, crash, restore, journal and
interop controls remain in place. The historical multi-right once fixture keeps
its original signed bytes; its unsigned expectations now record the stricter
refusal. The initial full-suite failures from the old expectation remain in the
implementation evidence, rather than being represented as original passes.
Synthetic time, registry and effect premises
establish no protected-provider or native qualification.
