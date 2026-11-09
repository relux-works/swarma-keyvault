# Hosted aggregate-deadline control

This isolated stdlib-only Go module is excluded from the ordinary repository
package walk. Its three real test binaries each perform 25 seconds of work,
create a descendant in a separate process group, and complete below a 45-second
binary timeout. The hosted workflow runs the same aggregate serially twice:
a two-minute step must succeed; a one-minute step must fail during the third
healthy binary. A final Go check requires both outcomes, actual binary witnesses,
the scaled deadline/cleanup time window, and no surviving recorded PID. Known
fixture PIDs are emergency-cleaned only after the observable survivor assertion.
The control packages are compiled during fixture preparation before these short
steps; each measured Go command still has its entire invocation inside the step
deadline. The product suite performs its own compilation inside its 30-minute
step. Serial package scheduling is explicit through `GOFLAGS=-p=1`.

The step shell has the same INT/TERM trap as the product suite. It retains the
entry process while the Go command is active so cancellation can escalate to the
whole tree, including descendants outside the original process group. This uses
the hosting runner's native [step deadline](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idsteps_timeout-minutes)
and [cancellation sequence](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation).
The deadline starts before the complete Go invocation; cancellation grace follows
it. This control does not change any product timing, isolation or sampling rule.

`KEYVAULT_SUITE_CONTROL` names an existing private absolute directory containing
private `positive` and `negative` directories. The workflow creates it under
`RUNNER_TEMP`, writes phase start times there, and sets `KEYVAULT_SUITE_PHASE` to
the selected phase. PID/completion witnesses stay there. This fixture uses no
network, credentials or vault keys. Do not point it at a live data directory.

Run deterministic record-contract tests locally:

```
go -C scripts/tests/testdata/suite-budget test -race -count=1 ./budget
```

The hosted result test skips without its explicit fixture environment. Record
tests reject missing starts, incomplete positive runs, binary-duration violations
and an incorrectly successful short aggregate, with neighboring valid cases.
They do not prove a hosted timeout. A follow-on job reads this completed job's
same-attempt log through the read-only Actions API and requires the exact native
step-timeout annotation. The token is the hosting platform's normal ephemeral
workflow token; the raw log stays in runner scratch. The Go annotation tests
reject generic failures, binary alarms and other step names or limits. An
unrelated failure, crash, skipped setup or per-binary alarm is not the intended
negative result. The positive fixture
uses the exact same code and command as the negative fixture. The dedicated job
is a test of the suite deadline, not another performance measurement lane.
