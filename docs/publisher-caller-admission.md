# Bounded publisher message admission

This source component implements the closed request codec, Go message admission
and the conditional typed publication sequence. It remains source-only and is
pending independent review and native implementation for private-operation
integration.

`internal/keyvault/publishergate` has **no native adapter or available production
key capability**. `NewReceiver` returns `native_unavailable` on every platform. Nil
and zero receivers also refuse. There is no public constructor taking caller
bytes, policy, PID, path or claimed peer facts. `DecodeRequest` returns syntax
only; `AdmittedRequest` records message admission only. Neither authorizes a
private operation. Both internal boundaries can be supplied only inside this
package; their only implementations are synthetic `_test.go` doubles.

The existing CLI, helper, Manager, backend and live publisher do not use this
component. This patch therefore does not satisfy the installed-key acceptance
criterion or close any existing generic/old-binary/blob route. There are no
actual protected key pins or policy values in this component. Existing protected
policy components coexist unchanged; there is no production integration with
this message/publication component.

## Implemented contract

The bounded JSON source codec accepts exactly these five fields:

```json
{"version":"publisher-call/1","op":"publish-current","scope_id":"synthetic-scope","policy_epoch":7,"request_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

The nonce above is a public synthetic example, not a credential. Nonces are
correlation/replay identifiers and never permission. Scope is 1–64 ASCII bytes;
epoch is a positive uint64 encoded as an integer, without decimal/exponent
notation. Nonce encoding is canonical unpadded base64url for exactly 32 bytes.
The source codec is at most 1,024 bytes and accepts a flat object, so nested
values fail immediately. Duplicate keys, including escaped aliases, unknown
members, wrong types, multiple messages and invalid UTF-8 refuse. This codec
does not implement an XPC dictionary or prove native preallocation bounds.

Admission first checks the protected policy projection, enabled state and
validity, then asks the sealed boundary to authenticate and copy one original
received message. It checks the closed schema, scope and epoch, cancellation,
current policy again and validity again after receive. It checks cancellation
once more after both final policy/time callbacks, before returning an admitted
request. Refusals expose only
typed bounded codes. Policy/native error text is not returned to the caller.
Each epoch must identify a complete immutable protected policy, including code
requirements and build admissions, even though the projection here has only
scope/epoch/enabled/validity. The final recheck is an admission check, not a
serialized private-entry fence or durable anti-rollback implementation.

## Conditional typed publication

`Receiver.PublishCurrent(ctx)` obtains its own message admission. Its public API
accepts no digest, admitted context, key selector, entries or destination. It
requires a second sealed boundary providing an exclusive per-key fence backed
by independently protected policy, qualified time, current replay state and
exclusive held-key custody. Absence of either boundary refuses before key access.

Within that conditional boundary the source:

- copies the protected policy's exact canonical entries bytes and SPKI, checks
  the entries SHA-256, closed entry shape, conflicting duplicates and existing
  snapshot syntax/64-entry limit;
- checks the explicit kind/service/purpose/generation/store/extraction/SPKI pin
  and refuses presence-constrained keys in this unattended operation;
- derives the complete snapshot, issued time, cadence slot, content ID and
  digest internally through the existing pinned snapshot builder;
- refuses missing/corrupt/rolled-back state and incomplete reservations, checks
  replay epochs, increasing slots and nonces, and returns the stored public
  receipt for an identical completed message without signing again;
- reserves exact intent durably before resolving a held key; checks that held
  object's public facts, revalidates the original message/current policy under
  the fence, then rechecks time, slot, key facts and cancellation;
- attempts one silent signature, verifies and assembles it against the immutable
  plan, then asks the fence to durably commit completion and atomic publication
  to the protected destination. No raw signature is returned to the caller.

The exact received message bytes are hashed for replay identity: a reused nonce
with different encoding also refuses. Replay is bounded to 65,536 records and
16 MiB of encoded protected state. Reaching the record cap refuses new work;
completed duplicate receipts remain available within policy validity. Records
are retained in strictly increasing slot order. Protected genesis, storage
integrity/currentness, complete-set continuity across epochs and durable
reservation/commit/crash recovery remain adapter obligations. A state boolean
or same-UID file is not proof of those properties.

All failures before signature entry have zero private calls. A signature error,
invalid result, cancellation after entry or failed completion/publication returns
`private_outcome_unknown`, retains the reservation and never retries. This code
does not establish a hard native timeout or undo an already entered operation.
Cooperative contexts bound request preparation to 5 seconds and private
call/completion to 15 seconds, preserving any shorter caller deadline. Boundary
implementations must honor them; synchronous native APIs may outlive a context.
Any pre-entry failure after reservation also leaves reconciliation to protected
authority. Fence contention must refuse without an unbounded pending queue.

The fence and held-object contracts are implementation requirements for a future
native adapter. The source has no fallback implementation, generic callback
constructor, file-backed authority or CLI switch that can activate them.
Message admission retains a sealed original-message witness alongside the
immutable payload hash. Missing witness evidence refuses; the final fence
revalidates that original witness against the same policy and payload hash.
The hash binds bytes to the witness and never substitutes for OS sender or
process identity. A native adapter must retain the actual received-message
evidence and qualify its lifetime, exec and forwarding semantics.

## Synthetic validation and its limits

Two independent paired tests cover sender and request admission:

1. Identical valid closed bytes from an admitted versus foreign synthetic peer.
2. One admitted synthetic peer with valid bytes versus those bytes plus exactly
   one spoofed `pid` field.

Within each pair, both cases use the same ephemeral software key, fixed
snapshot, policy and consumer. Only the stated variable changes. Each refusal
has zero synthetic private calls, zero publications and unchanged prior output.
Each positive has exactly one software ECDSA call and one complete
`revocation/1` envelope verified by the pinned assembler and independently by
stdlib ECDSA/content-id reconstruction. The consumer is test-only: it is not a
production publisher, durable replay implementation or custody capability.

Two additional paired controls cover cancellation in the final policy read
and cancellation in the final clock read, each beside an identical valid
neighbor. Cancelled consumers have zero private calls/publications and preserve
prior output; valid neighbors retain the verified single publication.

Typed-publication tests exercise the actual production orchestration with
synthetic message/policy/state/fence/held-key adapters. Their valid neighbors
make exactly one ephemeral software ECDSA call and verify the complete envelope
with both the pinned assembler and independent stdlib ECDSA/content-ID checks.
Pairs cover spoofed fields versus foreign peers, absent state, policy/entries
substitution, key tuple/store/SPKI/constraint mismatch, final key swaps,
revocation/expiry/slot changes, persistence failure and cancellation at each
pre-entry callback. Post-entry cases preserve reservations and refuse retries;
replay/cadence controls verify one signature per admitted slot and exact receipt
reuse. These tests establish Go ordering and output semantics only.

Other synthetic cases cover malformed/oversized input, absent/disabled/stale
policy, time bounds, cancellation, policy loss/revocation during receive and
missing native support. Fuzzing checks parser safety, input immutability and
accepted-request bounds. No native private API is invoked, including presence
probes. No synthetic positive establishes macOS sender authentication.

## Required before any private-operation integration

The following remain unimplemented and native validation is **NOT RUN**:

- OS message-peer requirement enforcement, actual-sender/exec/forwarding and
  attachment rejection, server identity and hardened-process qualification;
- exclusive existing-key custody and exclusion of aliases, generic commands,
  older executables, raw helper/blob restoration and alternate private APIs;
- independently protected policy/release/entries authority and actual durable
  current epochs, qualified time/replay storage, reservation persistence and
  crash reconciliation;
- actual admitted entries/destination/cadence and held-key facts, native
  enforcement of the serialized revoke/private-entry fence and durable
  publication, with no retries after uncertain private completion;
- platform/SDK/API and native resource/cancellation qualification, followed by
  independent exact-head implementation review and an authorized owner sitting.

Do not connect `AdmittedRequest` to `Manager.Sign`, a digest signer or the Swift
stdin helper. A public nonce, callback, same-UID file or synthetic boundary is
not the missing authority. Missing prerequisites leave this component disabled;
there is no PID/path/hash, interactive prompt or generic signing fallback.

## Open product decisions

Допуск: разрешаем запуск любой копии утверждённой программы или только конкретного задания?

Хранение: подтвердите способ хранения существующего ключа и защиту от других процессов того же пользователя без ослабления ограничений ключа.

Политика: кто независимо утверждает данные, версии программы и состояние повторов, чтобы обычный процесс пользователя не мог их заменить?

Платформа: подтвердите минимальные macOS/SDK, механизм проверки отправителя каждого сообщения и требуемую защиту процессов.

Нативные настройки: подтвердите точный ключ и его ограничения, данные и адрес публикации, расписание, сроки и безопасное восстановление.
