# Local grant provider attempt observations

`grants execute` includes `provider_attempt` when the local GitHub subprocess adapter is invoked. This is an unauthenticated local observation, not an authenticated provider attestation or proof that a request left the host.

| Classification | Observation | Limits |
| --- | --- | --- |
| `process-start-failure` | `exec.Cmd.Start` failed | No process start was established; durable intent still holds the use. |
| `http-response` | The selected subprocess emitted a complete supported HTTP response header block | Preserves the actual emitted status and an admitted request ID; the executable could fabricate output. |
| `transport-or-unknown` | No complete supported HTTP response header block was established | Process launch, exit, timeout, cancellation, receipt-only output and UNKNOWN do not establish a network send. |

The adapter adds `--include` to the existing single `gh api` POST. It accepts HTTP/1.0, HTTP/1.1 and HTTP/2.0 header blocks with LF or CRLF, case-insensitive header names and ordinary additional response headers. A body-only valid receipt remains accepted without inventing HTTP status or a request ID. A valid receipt on a nonzero process exit or an HTTP error does not establish success.

Only the numeric emitted status, a bounded GitHub hexadecimal colon-separated request ID (four or five groups, at most 16 hex digits per group and 128 bytes total), and fixed diagnostic codes are exposed. Unsupported request ID forms are omitted, without replacing or sanitizing them. Ambiguous, malformed, folded, control-bearing, duplicate request-ID or oversized header blocks establish no HTTP metadata, and the whole output is then refused: the body is discarded and the outcome is UNKNOWN. A second header block is not unwrapped: the first block's status stands and the rest is treated as the body, which is not a valid receipt, so the outcome is UNKNOWN. No authentication header, cookie, arbitrary header, response body, executable path, raw error or stderr is included in attempt diagnostics.

Response headers are bounded to 16 KiB, 128 lines and 1024 bytes per line. Stdout is bounded to that header budget plus the unchanged 64 KiB receipt limit; stderr is bounded to 8 KiB. Overflow is sticky and refuses the result. A complete header already captured before a later failure can still establish metadata. Diagnostics use only `response-unavailable`, `process-start-failed`, `http-response`, `http-metadata-unavailable`, `output-limit`, `deadline-exceeded`, `context-cancelled` and `process-exit-failed`.

The journal format is unchanged: reservation and intent remain durable before dispatch, and only the original validated receipt body is recorded on success. All post-intent uncertainty keeps UNKNOWN/use-held; there is no resend, retry, automatic release or DELETE. Attempt observations are transient and are not reconstructed during journal replay. A failed write of the outcome remains UNKNOWN even with a valid HTTP response.

Fake subprocess tests cover start errors, nonzero exit, deadline, cancellation, absent/partial/invalid output, HTTP success and refusal, bounded overflow, malicious controls and private synthetic sentinels. These fixtures qualify parsing and state behavior only. They do not exercise native macOS presence or actual GitHub execution.
