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

A candidate helper extends the body of an existing MU reservation frame with
`MUP1`: the existing nonce/allowance reservation, qualified time, authority expiry,
watermark and complete exact-ID history are one checksummed, synced frame in
`mu.journal`. It creates no second authority journal. The existing 276,784-byte
reservation-body limit remains; a complete history larger than that frame
refuses even if it fits the view limit. History is never chunked, truncated or
evicted. Replay accepts legacy reservations and the new candidate body; old
readers refuse the latter. Once an epoch contains a plan-aware reservation,
legacy reservation calls refuse, so rollback cannot silently omit its history.
Do not downgrade a journal containing this body.

The helper checks retained time/watermark floors and byte-identical history,
the exact request and grant/use bindings, and known durable revocations before
appending. Failed or short writes and uncertain sync acknowledgements poison
the current open handle. Reopening either reconciles a complete reservation or
refuses a partial frame. A late completed sync retains the entire reservation
and history while refusing before dispatch. Unknown outcomes and fresh-nonce
attempts cannot release a once hold. Existing snapshot marks and revocation
unions remain in the same MU journal.

This does **not** complete final admission. No exclusion mechanism yet spans
all authoritative registry, revocation, generation, time, history and restore
updates through final use. An immutable old view cannot establish currentness.
The view's receiver port therefore retains independently verified observations
but always refuses an effect candidate. The helper is not wired into production
dispatch. Its own 100 ms reservation fence and the advisory 100 ms fence are
separate; a single complete final-admission budget is still unfinished.
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
