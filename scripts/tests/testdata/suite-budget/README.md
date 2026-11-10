# Aggregate deadline and descendant controls

This isolated stdlib-only Go module is outside the root module's package walk. It supplies three real serial test binaries with 25 seconds of work each under independent 45 second Go alarms. Each owns a detached-session descendant. All witnesses/reports are synthetic process data in an explicit existing 0700 private fixture directory; no vault or key is used.

The hosted workflow builds the actual production Linux suite supervisor separately and uses `exec` to make it the step entry. It runs these distinct controls with `GOFLAGS=-mod=readonly -p=1`:

| Phase | Supervisor budget | Native step | Required result |
| --- | --- | --- | --- |
| positive |2min|3min| All three healthy binaries complete, success report and no witnessed PID remains. |
| deadline |1min|2min| Two complete; the third starts; supervisor-specific deadline/exit124, cleanup within 5 s, no witnessed PID remains. |
| native |2min|1min| Two complete; the third starts; catchable entry cancellation/exit130, strict PID absence and genuine same-attempt native timeout annotation. |

Both intentional negative steps permit failure only so the subsequent verdict can inspect the real result. A generic failure, setup refusal, missing witness, wrong cause or root status, inconsistent first-signal/observed-cause record, all-success aggregate, cleanup refusal/late cleanup or surviving PID fails the verdict. A separately started outsider's heartbeat must advance after both interruptions; merely observing a PID, which could be a zombie, is insufficient. The verifier terminates that known fixture outsider only after recording its surviving heartbeat.

The native annotation follow-on job reads the completed same-attempt control job through the normal read-only Actions API; raw logs remain in private runner scratch. A Go parser requires the exact native step/budget annotation and rejects generic exits, test-binary panics and unrelated annotations. The supervisor's own deadline is established independently by its actual exclusive result, completed-binary witnesses and strict cleanup checks. Native annotation alone cannot substitute for the supervisor's own timer.

```sh
go -C scripts/tests/testdata/suite-budget test -race ./budget
```

The local command checks record/result/annotation contracts. Hosted-only tests skip without their explicit evidence environment; these skips do not qualify runtime cancellation. Linux real lifecycle tests are in `tools/suiterunner`. Native vault custody is outside this fixture. Supervisor SIGKILL and host loss have no cleanup guarantee.
