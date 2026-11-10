# Verifier attribution coordinator

This Linux-only diagnostic tool executes the fixed order A,B,B,A, retaining
four separate process results. A is `fcaf645a6efce742a9778202873d8a7be69f172b`;
B is `82886f1d90e3136e1708699036f7990d12385cb2`. Check out these exact commits
separately and apply the independently inspected instrumentation patches.
Instrumentation does not move product work, remove durability or alter the
40-attempt-per-path, real-clock, 100 ms fence or timing criteria.

Build with Go 1.26.10:

```sh
go test -race -count=1 ./tools/verifierdiagnostic
go build -o /absolute/private/bin/verifier-diagnostic ./tools/verifierdiagnostic
go -C /absolute/source-b build -o /absolute/private/bin/suite-runner ./tools/suiterunner
/absolute/private/bin/suite-runner --timeout=24m -- \
  /absolute/private/bin/verifier-diagnostic \
  -a /absolute/source-a -b /absolute/source-b \
  -out /absolute/private/new-evidence \
  -supervisor /absolute/private/bin/suite-runner
```

The output path must be new, outside both source directories and under an
existing parent. Source directories must be distinct, regular directories with
the expected Git HEADs. Parent symlink aliases are resolved for comparisons;
a symlink in place of a source directory or supervisor is refused. The supervisor
must be a regular executable without group/other writes. The supplied supervisor
is the reviewed Linux process custodian; the coordinator adds no independent
process-tree cleanup implementation.

Prepare both dependency caches and compile both test binaries without executing
tests before collection. This is build preparation, not a product warmup. Each
collection starts a fresh process and receives its own private `RUNNER_TEMP` and source-specific `GITHUB_WORKSPACE`.
Each confined wrapper creates fresh isolated dependency and build caches; the
preparation binaries are not reused as measurement executables.
The supervisor bounds each complete confined command at five minutes. All four
commands are attempted after a process failure, no-start or missing telemetry.
The coordinator returns nonzero when any command or required evidence fails.
External aggregate cancellation can prevent completion; absent collections are
not promoted to success.

Each private collection directory retains `collection.log`, `supervisor.json`
and `verifier-attribution.trace`; `collections.json` records order, original
process exits, source pins and file hashes. `supervisor_started` records only
process startup, not test setup, sample collection or qualification. The evidence
presence field records byte retention, not the semantic validity of a report or
runtime trace. Inspect every raw sample, assertion and trace before attribution.
No environment, secret, key or journal payload is included in coordinator
metadata. Use only laboratory fixtures.

After all four commands finish, exact raw trace bytes are hashed and emitted as
compressed base64 between `VERIFIER_TRACE_GZIP_BASE64_BEGIN` and
`VERIFIER_TRACE_GZIP_BASE64_END`, preceded by their collection index, source and
SHA-256. Compression runs after collection so it cannot contend with later timed
children. Missing, empty, symlink, oversized (over 64 MiB raw or 4 MiB compressed)
or changing traces refuse capture; traces are never silently truncated. Exact supervisor reports (up to 64 KiB) also survive as base64 between
`VERIFIER_REPORT_BASE64_BEGIN` and `VERIFIER_REPORT_BASE64_END`, with their
collection/source and SHA-256. These witnesses preserve bytes without asserting
report semantics. Full
collection logs also stream to the diagnostic job log. Save the complete job log
to ignored local scratch before decoding and checking the raw trace hashes.

This instrumented experiment never qualifies a product head. A shared failure
shows non-uniqueness to one source; it does not prove an external infrastructure
cause. A candidate-only failure suggests an interaction, not its mechanism.
No reproduced stall remains inconclusive about historical failures. Do not
extend the fixed collection count, select the best run or subtract trace overhead.
