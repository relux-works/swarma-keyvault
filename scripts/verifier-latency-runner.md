# Hosted verifier runner prerequisite

The measurement runs once, with zero retries or warmup exclusions. It prepares
an independent fixture for every attempt on each path, records all 40 attempts
per path even after a refusal, and confirms fixture cleanup after every attempt.
Construction/advisory requires all 40 qualified successes, nearest-rank p95
<=80ms and every sample <100ms. Final Handle completion requires a proven durable
success or a genuine no-effect deadline refusal for each attempt, with at least
one actual success among the 40. Final p95/max and late completion counts are
reported metrics; they have no full-return latency threshold. Incomplete attempts,
state/storage/cancellation errors, missing durable/dispatch proof and cleanup
failures still fail. The original absolute 100ms admission/dispatch fence remains.
Persistence stays synchronous, including after expiry; a timely effect may report
truthful success after its durable outcome completes late.

Logs separate observed elapsed distributions (including refused measurements)
from successful qualification counts and refusal classes. A deadline class comes
only from an actual deadline fence, never from elapsed time or the generic
state-unavailable sentinel. It does not establish environmental noise or grant
a successful effect. A safe deadline completion additionally needs actual no-effect
and reopened-journal proof. Other state and storage refusals remain failures.
Deadline errors retain their existing text, `errors.Is` sentinel chain and
`errors.As` platform refusal code. Private test observers provide monotonic
start/end offsets for domain locking, lock/open, journal replay, real verification,
reservation/fsync, intent/fsync and outcome/fsync inside final admission. Unreached
phases remain absent; incomplete brackets fail evidence validation. The observers
are installed only by same-package tests and supply no authority or clock.

The confined invocation also runs deterministic injected-result controls: early
refusals must leave both paths' remaining attempts intact; unproven refusals fail;
deadline/state refusals must stay distinct at equal elapsed values; in-budget
successes and proven late completions pass; all-refused final series, invalid counts,
incomplete samples, joined errors and missing proof or cleanup errors refuse.
These controls run on Darwin and Linux, including race builds. They prove gate
logic and fence behavior, not hosted timing or namespace qualification.

The non-race verifier job fixes `runs-on: ubuntu-24.04` (amd64). The runner
owner permits the exact official Ubuntu archive bubblewrap package, including
its postinst sysctl, only on the disposable GitHub-hosted VM for this job.
Self-hosted runners, Macs, shared hosts and local VM execution are forbidden.
After package setup, the separate guarded workflow step permits exactly
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` on that disposable
VM before timing. No other manual policy change is permitted. The
measured-process isolation is unchanged.

Setup requires Actions `runner.environment=github-hosted`, Linux/X64, actual
Ubuntu 24.04/amd64 and the runner image identity/version. The fixed workflow
checks out its setup helper at `github.workflow_sha` and the helper verifies its
checkout HEAD against that immutable SHA. These are platform context values,
not dispatch inputs. The SHA binds the reviewed workflow/setup source; the
Ubuntu label is not itself privilege proof or an immutable image. Retain the
actual image version and SHA in the log. These shell guards do not grant
permission to invoke setup directly on another host by forging environment
variables. Workflow changes still require independent review and publication.

Setup downloads only
`https://security.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.3_amd64.deb`
with HTTPS and no redirects. It checks SHA256
`2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094`,
then package name, exact version and amd64 metadata before `sudo dpkg --install`.
There is no alternate source, version, dependency installation or retry. The
installed version/architecture must match. The pinned official postinst may
set `kernel.unprivileged_userns_clone=1`; the package and postinst are unchanged.

The userns step independently checks the same trusted Actions context, immutable
workflow checkout, ImageOS `ubuntu24`, actual Linux/x86_64 and Ubuntu 24.04/amd64.
Wrong or missing context fails before any policy write. Context is passed through
quoted shell variables in step environment entries, never dispatch input or a
job-level runner expression. Environment values alone do not authenticate an
arbitrary local caller: operating authority exists only in this reviewed workflow.
Both knobs are read BEFORE and AFTER the single write, including on failure.
Read/write failures propagate, the first primary failure wins, and success
requires the resulting AppArmor userns knob to equal zero. A logging failure
also fails the workflow step. Offline inert controls exercise these paths without
invoking privileged commands or changing the test host.

The actual setup log records the expected version, official source, downloaded
.deb SHA, installed version and BEFORE/AFTER reads of both
`kernel.unprivileged_userns_clone` and
`kernel.apparmor_restrict_unprivileged_userns`. Failed reads are explicitly
`unavailable` with their actual read exit and diagnostic, never synthetic zero.
An EXIT trap records available AFTER evidence on download/verification/install
failure and retains the primary nonzero status. The workflow's pipefail makes
setup failure a job failure before measurement; its always-run summary retains
both setup and measurement logs. Namespace refusal is an explicit job failure
with the original diagnostic and no numeric p95 result.

Actual hosted execution is **UNMEASURED**. Offline command shims validate
control flow only; this source disposition is not runtime qualification.

The launcher requires bwrap before provisioning dependencies. It uses the same
`--unshare-all --clearenv` sandbox for a non-product preflight and measurement.
The preflight checks read-only source, toolchain, tools and dependency mounts,
0700 private scratch directories, a cleared credential environment and the
exact go.mod toolchain. An explicit `toolchain goX.Y.Z` selects the pin; when
omitted, the exact patch `go X.Y.Z` directive supplies it, following
[Go's implicit toolchain rule](https://go.dev/doc/toolchain#module-and-workspace-configuration).
The stdlib-only `tools/verifiertoolchain` utility invokes `go mod edit -json`
inside the sandbox, using the authoritative module grammar. Comments and EOF
without a newline remain valid; duplicate directives and extra arguments
refuse. A language-only `go` minimum is valid with an explicit exact toolchain.
Without that explicit pin, this gate requires a patch-level `go` directive.
The selected toolchain must also meet the module's minimum Go version.
It requires exact runtime equality for reproducible measurements. Grammar,
missing/malformed pin and version failures stop before dependency provisioning
or product startup. Building/running this preflight utility is qualification
work, not a product test or a timing sample. Starting the
sandbox also tests whether the runner permits the required namespaces. A
successful package install alone does not qualify them.
Dependency provisioning uses a new private cache, a cleared environment and
canonical public Go checksums. Product tests run offline in the sandbox.

Missing bwrap reports exit 127. A failed preflight retains its original stderr
and exit status, explicitly says no timing samples were collected and stops
before dependency provisioning or product startup. These are setup failures,
not measured latency failures. The pipeline retains nonzero exit status through
`pipefail`; the existing always-run summary step preserves any recorded output.

On exit, a bounded cleanup uses inherited descriptors for this invocation's
private state. It grants owner write permission only on owned directories after
execution, never on files or symlink targets, and refuses mount boundaries and
changed directory identities. Read-only sandbox mounts remain unchanged.
Cleanup has a 12-second timeout with a 2-second forced-termination bound,
100,000-entry limit and depth limit 128, without retries. A cleanup error is
reported separately; an existing nonzero primary exit is retained, while a
successful primary exit becomes 74. HUP/INT/TERM/PIPE exit 129/130/143/141 and run the
same cleanup. SIGKILL and machine loss cannot be trapped. Python 3 and GNU
timeout are runner-side cleanup prerequisites, checked before state creation.

If the hosted runner denies namespaces, stop for its owner to qualify a route
within the existing isolation and policy contract. This candidate does not
select another runner, install an AppArmor override, change any further
namespace restriction, share networking, use sudo for tests or run the verifier
outside the sandbox. If loopback RTM_NEWADDR still fails, preserve its raw error
and stop with zero samples, without retries. The scoped disposable-hosted
permission grants no authority on a shared host, self-hosted runner or Mac.
The namespace preflight must succeed on that runner before any measurement.

The offline shell fixtures in `tests/verifier-latency-confined-test.sh` check
missing-tool diagnostics, original namespace refusal status/stderr, cleanup and
no product startup. Their Go shim and any namespace refusal are explicitly
labelled; they are neither real toolchain nor performance qualification.
`go test -race -count=1 ./tools/verifiertoolchain ./scripts/tests` runs the actual
Go module parser for the accepted/forbidden pin forms and checks the actual
outer refusal fragment's diagnostic/status preservation. It does not qualify
a sandbox or latency. The namespace-closure shell fixture uses a clearly
labelled utility shim and does not claim real toolchain qualification.

The product's 100ms admission/dispatch fence, exactly 40 attempts per path and
zero retries remain. Only construction/advisory has p95 <=80ms and max <100ms
latency thresholds; final synchronous completion has the correctness gate above.

Official platform references:

- [Ubuntu package inventory](https://packages.ubuntu.com/noble/amd64/bubblewrap/filelist)
- [Ubuntu package versions](https://packages.ubuntu.com/bubblewrap)
- [Ubuntu namespace and AppArmor policy](https://discourse.ubuntu.com/t/ubuntu-24-04-lts-noble-numbat-release-notes/39890)
- [Bubblewrap sandbox construction](https://github.com/containers/bubblewrap/blob/v0.9.0/README.md)

- [GitHub runner context and workflow SHA](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
- [GitHub-hosted runner VM lifecycle and labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

Both workflow logging pipelines capture `PIPESTATUS` immediately after the
pipeline, with errexit disabled only for that pipeline and capture. A nonzero
install/verifier status wins over a simultaneous logging failure, including
signal statuses 129/130/143/141. If the primary succeeds, a nonzero tee status
still fails the step. Offline fixtures execute each production run block
verbatim; package commands are inert and the verifier uses the exact cleanup
helper with an owned populated 0555 cache. These controls qualify status
selection only; hosted package setup and timing remain UNMEASURED.
