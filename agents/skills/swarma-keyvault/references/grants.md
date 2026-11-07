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

## Offline verify: runnable inert public example

When execution of public examples is authorized, use the committed
[`assets/local-verify/`](../assets/local-verify/) triplet with the portable CLI.
It was serialized from `localTestFixture` / `localFixture.envelopes` in
`internal/grants/local_request_test.go`; only public SPKIs and signed envelopes
are included. The ephemeral software private keys were never serialized.
The fixed owner name and repository are required by this local profile's parser;
the synthetic public pins do not enroll that owner or authorize that repository.
Never install this enrollment as a runtime trust configuration.

On Linux with `bwrap`, from the repository root, supply the absolute path to a
separately built, reviewed portable `cmd/swarma-keyvault` binary (`CGO_ENABLED=0`):

```sh
(
scratch=$(mktemp -d /tmp/keyvault-public-verify.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
mkdir -m 700 "$scratch/home" "$scratch/tmp" "$scratch/cache"
bwrap --die-with-parent --new-session --unshare-all --clearenv \
  --ro-bind /usr /usr --symlink usr/bin /bin \
  --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --proc /proc --dev /dev --tmpfs /tmp \
  --ro-bind "$PWD/agents/skills/swarma-keyvault" /skill \
  --ro-bind /absolute/offline-build/swarma-keyvault /keyvault \
  --bind "$scratch" /work --chdir /work \
  --setenv PATH /usr/bin:/bin --setenv HOME /work/home \
  --setenv TMPDIR /work/tmp --setenv XDG_CACHE_HOME /work/cache \
  /bin/sh /skill/scripts/verify-public-example.sh /keyvault /skill/assets/local-verify
)
```

The confinement command above mounts the binary, skill and system tools
read-only, clears the environment and unshares all namespaces. HOME, TMPDIR and
cache are private absolute directories; no host home, credential directory,
socket or caller cache is mounted. The helper
[`verify-public-example.sh`](../scripts/verify-public-example.sh) then runs just
`grants verify` twice; it relies on this caller-established confinement. Do not
invoke the helper outside it. The example neither builds nor downloads anything.
If confinement is unavailable, stop without a direct-execution fallback. Cleanup
removes only newly created scratch directories. Fixture state/provider paths
deliberately do not exist, and this stateless verification route accesses neither.

The accepted observation uses `--at 2026-11-02T11:00:00Z`: exit 0 and one
stdout object with `verdict:"accepted"`, `certificate_id:"certificate-A"`,
`request_id:"request-A"`, `action:"repository.create"` and
`expires_at:"2026-11-02T11:30:00Z"`. It establishes only the public checks for
these synthetic inputs, not a reservation, live grant service or effect right.

The neighboring refusal changes only `--at` to `2026-11-02T11:30:00Z`, the
request's exclusive expiry: exit 1, empty stdout and
`refused: grant validity has expired` plus LF on stderr. The same certificate,
request and public pins still verify cryptographically; the half-open validity
interval causes this refusal. The helper reports both observations and fails
if the expired case succeeds or emits stdout. `--at` is a test observation;
never use it to make an expired real grant appear current. There is no signing,
key creation, Keychain access, network projection, state initialization, provider
execution or model/runtime launch in this example.

## Meaning of the verdict and execution failure

`verify` loads the separate enrollment, owner/requester pins, signatures, exact
subject/audience/cycle/use/target and validity. It does not access Keychain,
open/create state, lock, reserve, check replay or launch a provider. Limits are
8,192 config bytes, 98,304 certificate bytes, 12,288 request-envelope bytes.
`--request -` reads stdin; config/certificate cannot be stdin. Default time is
sampled after input reads; `--at` is a test observation. Usage exits 2; refusals
exit 1; discard stdout after any nonzero exit, including output-write failure.
`TestLocalVerifyCLIOutput`, `TestLocalVerifyCLIUsage` and
`TestLocalVerifyCLIInputs` in `cmd/swarma-keyvault` specify these exit codes,
stdout and stderr.

`execute` is an effect route, not an agent step: run it only with the
custodian's authorization for that exact request. It uses the enrolled
provider/state, locks and rechecks, reserves and syncs intent before dispatch. It may return `succeeded` or `unknown`.
UNKNOWN, lost output, interruption or journal corruption require preserving
state and a custodian decision; do not resend with a new request ID, truncate,
reset or release the held use. Changing configuration bytes changes the local
epoch; it is not migration. This local proof of concept supplies no live Matrix
intake, protected clock, revocation/reissue workflow or same-UID isolation.
