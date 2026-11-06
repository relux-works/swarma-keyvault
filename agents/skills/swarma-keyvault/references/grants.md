# Typed repository grants and offline verification

Source: `cmd/swarma-keyvault/{main,issue,local,local_verify}.go`,
`internal/grantissuer/repository.go`, `internal/grantrequester/request.go` and
`internal/grants/{local_enrollment,local_config_file,local_mediator}.go`.

## Keep the profiles separate

| Command after `swarma-keyvault grants` | Flags and effect |
| --- | --- |
| `prepare` | `--plan FILE\|- --owner-mxid MXID --issuer-spki-der FILE`; unsigned repository payload and review |
| `local-prepare` | Same plus `--requester-spki-der FILE`; distinct local certificate/requester binding |
| `issue` | `--payload FILE\|- --owner-spki-der FILE`; OWNER-SITTING typed owner signature |
| `local-issue` | Same plus `--requester-spki-der FILE`; OWNER-SITTING local-profile signature |
| `request` | `--payload FILE\|- --requester-spki-der FILE`; OWNER-SITTING private requester signature |
| `verify` | `--config FILE --certificate FILE --request FILE\|-`, optional test-only `--at RFC3339`; stateless public check |
| `execute` | `--config FILE --certificate FILE --request FILE\|-`; separately authorized provider effect and durable accounting |

Prepare is public-only and creates no key, signature or active rights. Inputs
are complete canonical JSON, not fields to infer. Preserve exact bytes,
domain and profile: local certificate `grants-local-certificate-1`, signed
local envelope `grants-signed-local-certificate-1`, request envelope
`grants-local-request-2`. `grants issue`'s original certificate format is not
accepted as a local certificate. Local subject has `account_mxid` and `device_id`,
not a Matrix device-key proof; `encrypted-dm` is a declared label, not E2EE.

The issue/local-issue slice fixes owner `@alexis:gr.relux.works`, address
`alexis/grants-owner-v1`, generation 1, and target
`relux-works/matrix-grants-poc-261031`: first issue, one cycle, private CREATE
and paired single-use DELETE, no supersedes. The local executor dispatches only
CREATE. It is not a general repository administrator. Typed signing validates
payload/pins before constructing the manager and gates the actual owner key on
exact SPKI, Enclave store, presence and extraction `none`. Review is written
immediately before the private call. Denial or failed review ends the attempt.

`request` selects `swarma-grants/requester-local-v1`, generation 1, Enclave,
non-presence, extraction `none`, exact separate requester pin. **OWNER-SITTING**
still applies: do not invoke private signing as an agent step. Request signing
checks its signature, not a certificate's allowance.

## Offline verify: inert public TEST example, do not run

The repository has public software-fixture *source*, not a committed ready-made
local enrollment/certificate/request triplet. This example denotes externally
staged public-only serializations from `localTestFixture`, `localFixture.envelopes`
and `localVerifyInputs("valid")` in
`internal/grants/local_request_test.go` and `local_verify_test.go`. No fixture
was generated or executed for this skill. The paths below are staging
placeholders, not asserted repository files or live enrollment. The canonical
config must be a current-user-owned regular 0600 file, not a symlink. It contains
only public pins and declared context; its state/provider paths need not exist.

Accepted neighbor, using those matching public TEST inputs:

```text
swarma-keyvault grants verify --config /absolute/public-test/enrollment.json --certificate /absolute/public-test/certificate.json --request /absolute/public-test/request.json --at 2026-11-02T11:00:00Z
```

Expected from source: exit 0, one stdout JSON object without a newline,
`verdict:"accepted"`, `certificate_id:"certificate-A"`, `request_id:"request-A"`,
`action:"repository.create"`, private fixed target, checked UTC `valid_at` and
exclusive `expires_at:"2026-11-02T11:30:00Z"`.

Adjacent actual verify refusal, same exact inputs at their exclusive expiry:

```text
swarma-keyvault grants verify --config /absolute/public-test/enrollment.json --certificate /absolute/public-test/certificate.json --request /absolute/public-test/request.json --at 2026-11-02T11:30:00Z
```

Expected: exit 1, empty stdout, stderr
`refused: grant validity has expired` plus LF. This is `ErrExpired` from the
real check; `TestLocalVerifyBoundaries` and `TestLocalVerifyRefusals` specify the
accepted neighbor and expiry refusal. These are static expectations, not results
of a run. Never use `--at` to make an expired real grant appear current.

## Meaning of the verdict and execution failure

`verify` loads the separate enrollment, owner/requester pins, signatures, exact
subject/audience/cycle/use/target and validity. It does not access Keychain,
open/create state, lock, reserve, check replay or launch a provider. Limits are
8,192 config bytes, 98,304 certificate bytes, 12,288 request-envelope bytes.
`--request -` reads stdin; config/certificate cannot be stdin. Default time is
sampled after input reads; `--at` is a test observation. Usage exits 2; refusals
exit 1; discard stdout after any nonzero exit, including output-write failure.

`execute` uses the enrolled provider/state, locks and rechecks, reserves and
syncs intent before dispatch. It may return `succeeded` or `unknown`.
UNKNOWN, lost output, interruption or journal corruption require preserving
state and a custodian decision; do not resend with a new request ID, truncate,
reset or release the held use. Changing configuration bytes changes the local
epoch; it is not migration. This local proof of concept supplies no live Matrix
intake, protected clock, revocation/reissue workflow or same-UID isolation.
