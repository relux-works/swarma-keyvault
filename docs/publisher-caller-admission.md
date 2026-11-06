# Bounded publisher message admission

This source component implements only the closed request codec and the Go
message-admission ordering from fjjp5t design r1. The design SHA-256 is
`f8674621efd24a48cd55ef2f004ca0a8412802276b10826405e5f93b77cec028`, reviewed
as conditional architecture by independent review 402. Original source baseline was
`1564731cb6157ddca9fcf8a4dae3d4bde71287c6`; this revision is composed on main
`16e0fe6d0898b8cb0e8f9ce236dd9cef87e14ff0`, including landed PR69 unchanged. Implementation authority is
Sirius's 2026-11-06 disposition, item 5, event
`$lz4IEa5kPxUzrQS9txzVkoduTJtJk02ULadyrS94xmc`.

`internal/keyvault/publishergate` has **no native adapter and no private-key
operation**. `NewReceiver` returns `native_unavailable` on every platform. Nil
and zero receivers also refuse. There is no public constructor taking caller
bytes, policy, PID, path or claimed peer facts. `DecodeRequest` returns syntax
only; `AdmittedRequest` records message admission only. Neither authorizes a
private operation. The internal boundary can be supplied only inside this
package; currently its only implementation is a synthetic `_test.go` double.

The existing CLI, helper, Manager, backend and live publisher do not use this
component. This patch therefore does not satisfy the installed-key acceptance
criterion or close any existing generic/old-binary/blob route. There are no
actual protected key pins or policy values in this component. The landed PR69/398 source components coexist unchanged; this revision adds
no production integration between them and message admission.

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
request (KV470-M01). Refusals expose only
typed bounded codes. Policy/native error text is not returned to the caller.
Each epoch must identify a complete immutable protected policy, including code
requirements and build admissions, even though the projection here has only
scope/epoch/enabled/validity. The final recheck is an admission check, not a
serialized private-entry fence or durable anti-rollback implementation.

## Synthetic validation and its limits

KV402-L01 is split into two independent tests:

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

KV470-M01 adds two more paired controls: cancellation in the final policy read
and cancellation in the final clock read, each beside an identical valid
neighbor. Cancelled consumers have zero private calls/publications and preserve
prior output; valid neighbors retain the verified single publication.

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
- independently protected policy/release/entries authority and durable current
  epochs, clock/replay state, bounded reservations and crash reconciliation;
- fixed admitted entries/destination/cadence, actual held-key pin/constraint
  verification, serialized revoke/private-entry fence and verified durable
  publication, with no retries after uncertain private completion;
- platform/SDK/API and native resource/cancellation qualification, followed by
  independent exact-head implementation review and an authorized owner sitting.

Do not connect `AdmittedRequest` to `Manager.Sign`, a digest signer or the Swift
stdin helper. A public nonce, callback, same-UID file or synthetic boundary is
not the missing authority. Missing prerequisites leave this component disabled;
there is no PID/path/hash, interactive prompt or generic signing fallback.

## Owner batch for Sirius

Допуск: разрешаем запуск любой копии утверждённой программы или только конкретного задания?

Хранение: подтвердите способ хранения существующего ключа и защиту от других процессов того же пользователя без ослабления ограничений ключа.

Политика: кто независимо утверждает данные, версии программы и состояние повторов, чтобы обычный процесс пользователя не мог их заменить?

Платформа: подтвердите минимальные macOS/SDK, механизм проверки отправителя каждого сообщения и требуемую защиту процессов.

Нативные настройки: подтвердите точный ключ и его ограничения, данные и адрес публикации, расписание, сроки и безопасное восстановление.
