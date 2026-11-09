# Complete-suite supervisor

This dedicated Linux executable bounds one complete command and owns all descendants of that command. It sets `PR_SET_CHILD_SUBREAPER` before child launch, installs catchable signal handling before dispatch and starts the aggregate clock before the child's executable lookup/start. Child compilation and package scheduling are inside that clock. Building the supervisor itself is separate setup.

```sh
mkdir -p .temp
go build -o .temp/suite-runner ./tools/suiterunner
MAC_KEYVAULT_SKIP_KEYCHAIN=1 .temp/suite-runner --timeout=30m -- go test -race -count=1 -timeout=30m -v ./...
go test -race ./tools/suiterunner
```

`--timeout=DURATION` accepts positive durations up to 30 minutes; the default is 30 minutes. `--report=/absolute/private-directory/result.json` optionally creates an exclusive 0600 JSON result in an existing 0700 directory. Unknown/repeated options, missing `--`/command, relative report paths, nonprivate report parents and existing result files refuse before dispatch. Arguments and environment are never echoed. Reports/logs belong in ignored `.temp/` locally or private runner scratch in CI.

On normal root exit, root failure, its deadline or SIGINT/SIGTERM, one five-second cleanup budget covers root termination/reaping and descendant draining. Exactly one `exec.Cmd.Wait` owns the root. After that completes, only this supervisor's direct/adopted children are enumerated through `/proc/self/task/*/children`, killed and reaped with `wait4` until ECHILD. Killing intermediate parents makes their remaining descendants directly adopted; separate process groups and sessions do not escape this custody. No global process scan, pattern kill or unrelated process group is used. This is a dedicated executable; embedding it in a process with other children is unsupported.

| Result | Exit | Meaning |
| --- | ---: | --- |
| success |0| Root exited0 and no owned children remain. |
| exit | Root's positive exit, or1 for a signal | Original root failed; descendants were reaped. |
| deadline |124| Aggregate budget expired; root/descendants were reaped. |
| canceled |130| Catchable entry cancellation; root/descendants were reaped. |
| start-refused |127| Child could not start. |
| cleanup-refused, subreaper-refused, unsupported |125| Required process custody could not be established/completed; no weaker fallback. |
| Invalid arguments/report |64| Refused before dispatch. |

The JSON `reason` is the final classification; `cause` retains the primary root/deadline/signal cause if cleanup fails. `root_exit` retains the root's status (`-1` when unavailable/signaled); `reaped` becomes true only after ECHILD (or pre-dispatch cancellation with no child). `elapsed_ns` uses the monotonic command/cleanup interval. A failed result write also exits 125. Native step 32 minutes and job 40 minutes are separate fallback bounds around the production 30 minute invocation.

The runtime explicitly refuses outside Linux. Portable option/report tests can run on macOS; they do not qualify Linux custody. Linux tests use real successful/failed/orphaned/timed-out roots, detached descendants, serial individually healthy binaries and an unrelated sibling with an advancing heartbeat. An injected drain error checks truthful failure propagation alongside the real lifecycle controls. Hosted scaled own-deadline and native-cancellation controls are separate; see [the fixture contract](../../scripts/tests/testdata/suite-budget/README.md).

There is no cleanup guarantee after supervisor SIGKILL, host loss or an unresponsive kernel. A cleanup refusal/expiry remains failure, and successful source/static checks do not qualify native vault custody.
