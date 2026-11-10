# Bounded local verification view candidate

This is an uninstalled, partial implementation. Protected reads and the new
provider's final effects remain disabled. It supplies no principal, transport,
read admission, native service or actual GrantRoot installation. Existing
GrantRoot custody is an explicit installation premise; no Matrix-master or
one-year root-grant chain is claimed. A grant never supplies request A2.

The internal staging constructor accepts an explicit complete history and
qualified state, exact request and original policy/evidence records. It rejects
nil history and opaque assurance. Only explicitly supplied A1 grant-scope
assurance can be staged; an A2-required grant refuses with the existing
`grant_assurance_insufficient`. No request assurance is inferred from a grant.
The existing production issuer's assurance minimum is unchanged.

Staging checks the complete projected content before copying or parsing:
1 MiB including strings, original bytes and conservative content overhead;
128 records, including policy identity records and nonempty historical records;
4,096 total ID bindings; existing envelope, text and 8,192-byte signed-evidence
limits. The view-content budget is not a process RSS guarantee. Empty historical
values still occupy bindings and content budget; they are not invented as a
fallback or removed to make a candidate fit. Copies preserve original bytes and
nil-versus-empty distinctions. Caller mutation must be excluded during staging;
after construction, input mutation and result mutation cannot alter the view.

The source must supply its original monotonic observation instant paired with
qualified Now; a serialized or wall-only instant refuses. Construction never
resets it. The 2-second staging budget includes elapsed
time since that observation. A local monotonic fence narrows to the earliest
original authority, request, grant, caveat, attestation or snapshot-freshness
expiry. Restaging preserves the same fence. This local fence supplies no trusted
time, currentness or continuity. Staging and advisory verification run finite
bounded in-process work, with no backend callback or timeout goroutine.

The advisory path invokes the existing verifier and refuses if its work exceeds
100 ms or the original fence. Private diagnostics are a fixed status string
below 1,024 bytes, without source errors or protected payload. The real verifier
now retains both message and authorization plans, their original ID bytes and
watermarks in internal candidate metadata. Unsupported plan members refuse.

A candidate helper writes a new typed `MUP1` reservation body within the existing
outer checksummed MU journal framing: the existing nonce/allowance reservation,
qualified time, authority expiry,
watermark and complete exact-ID history are one checksummed, synced frame in
`mu.journal`. It creates no second authority journal. The existing 276,784-byte
reservation-body limit remains; a complete history larger than that frame
refuses even if it fits the view limit. History is never chunked, truncated or
evicted. Replay accepts legacy reservations and the new `MUP1` body; the old
`MUR1` reader refuses `MUP1`. Once an epoch contains a plan-aware reservation,
legacy reservation calls refuse, so rollback cannot silently omit its history.
A journal containing `MUP1` must not be downgraded.

The helper checks retained time/watermark floors and byte-identical history,
the exact request and grant/use bindings, and known durable revocations before
appending. Failed or short writes and uncertain sync acknowledgements poison
the current open handle. Reopening either reconciles a complete reservation or
refuses a partial frame. A late completed sync retains the entire reservation
and history while refusing before dispatch. Unknown outcomes and fresh-nonce
attempts cannot release a once hold. Existing snapshot marks and revocation
unions remain in the same MU journal.

The standalone view does **not** establish final-admission currentness. Its
receiver port retains independently verified observations but refuses an effect
candidate. The separate `LinuxAdmissionDomain` owns exclusion from authoritative
replacement/invalidation through Handle, real re-verification and effect entry,
using one original 100 ms admission deadline before contention and journal open.
This in-process exclusion supplies no protected-source identity or independent
restore fence and does not install a production effect executor.
Synchronous filesystem writes/fsync cannot be forcibly bounded or cancelled by
the existing port. Late-result refusal prevents an effect but establishes no
100 ms storage-return guarantee. No timed-out operation is left running.
Independent restore fencing and original observation/time custody remain
explicit protected-source premises, not properties proved by these helpers.

The API contract revision remains
`af3010961ad85bc9ad121bf6d6f998e50899d4d9`; the implementation base remains
`d9e5b2143f2cf1808558231b10b34c2dc0731390`. Dependencies, requester callback
tests, skill bytes and historical signed fixtures are unchanged. This candidate
requires fresh review of the complete revision and a new acceptance marker.

## Deterministic fence tests and real-time gate

The admission implementation has a package-private clock/deadline seam. Public
construction always uses the real monotonic clock and the unchanged 100 ms
final fence. No environment variable, production build tag, public constructor
or caller-supplied clock selects test time. Signed authority instants and
original observation/expiry pairing remain separate from local elapsed time.

Race-instrumented fence, refusal and acceptance tests use a clock owned by each
fixture and run the actual signed verifier. They explicitly advance through
expiry, contention, reservation sync and intent sync, while retaining context
cancellation, exclusion, persisted holds, refusal observations and effect
ordering. Synthetic elapsed time does not authenticate evidence or qualify any
provider, storage, clock, restore or native custody premise.

Hosted CI also runs `TestLinuxRealVerifierP95` without race instrumentation.
It records all 40 fresh attempts for each path: provider copy/construction plus
real advisory verification, and staged-domain final admission through actual
journal reservation, intent, fixture effect and outcome. Ephemeral key/signature
and fixture setup occur outside timing; verifier construction remains inside
advisory timing. Every attempt retains its raw monotonic duration, phases,
refusal class and cleanup result. One run, zero retries, no warmup or replacement
samples are permitted, including after an early refusal.

Construction/advisory still requires all 40 qualified successes, nearest-rank
**p95 <= 80 ms AND maximum < 100 ms**. Final admission instead checks synchronous
completion correctness: each attempt must either succeed with exactly one
fixture effect entered before its original context deadline, or return a genuine
private-tagged deadline refusal with no effect. After the timed Handle returns,
the test reopens the actual journal and checks both signed snapshot observations,
their monotonic unions, and any committed verification originals, nonce, once-use
reservation, dispatch intent and outcome. An unknown result retains its use and
intent. A storage/state/cancellation error, missing proof, malformed phase or
cleanup failure still fails. At least one actual final success is required;
refusing every attempt cannot qualify the path. Refusals remain refusals in logs.

Final Handle completion latency is reported separately: p95, maximum, all 40
ordered raw values, successful completions, safe deadline completions and the
number completing at or after 100 ms. These completion statistics have no latency
threshold. The original absolute 100 ms admission/dispatch fence remains in
place before contention and journal open. Persistence is synchronous: an expired
request waits for its in-flight journal operation to finish before returning,
and no effect may start after the fence. An effect admitted in time can finish
its durable outcome later and still return truthful success. No asynchronous
pending operation, detached persistence, retry or refund is introduced.

`LinuxDomainPrerequisites` retains its existing Clock, Continuity and
StorageReturnBound fields and admission predicates, including a positive declared
storage bound no greater than 100 ms. A caller declaration is not a measured
filesystem guarantee or a full Handle-return SLA. A passing fixture run neither
qualifies an unmeasured storage target nor supplies either clock or continuity.


Nearest-rank p95 is `sorted[ceil(95*N/100)-1]`, rank 38 of exactly 40.
Statistics sort a copy, preserve ordered raw measurements and reject missing,
extra or negative durations. Integer nanoseconds cannot represent NaN or infinity.
Construction's 80 ms boundary is inclusive and its 100 ms maximum exclusive.
Deterministic controls exercise late snapshot, reservation, intent and outcome
persistence, lost acknowledgments and cancellation; a held Sync cannot yield an
early terminal result. Gate controls pair valid late completions with forbidden
late dispatch, missing durability proof, joined storage failures and all-refused
series. They prove the exercised ordering and gate logic, not hardware power-loss
safety or performance of an unmeasured deployment.

The earlier latency-gate receipts remain failures under their original criterion;
they are not retroactively accepted. A new exact candidate requires its own fresh
review and hosted race plus non-race completion/construction result. Race logic
success alone does not establish real-time performance or qualify a deployment.
