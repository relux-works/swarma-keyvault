# SSH interface and new dedicated keys

## OWNER-SITTING only

Source: `cmd/mac-keyvault/ssh_agent.go`, `internal/keyvault/ssh_agent.go`,
`internal/keyvault/ssh_sshsig.go` and `docs/keyvault-ssh-new-keys.md`.
This reference describes selection and refusal boundaries, not installation or
key creation instructions. The owner provisions new dedicated keys separately.
Preserve existing SSH keys, host selection, agent jobs, Git settings and
historical verification trust. Do not import or replace an existing private key.

Starting `mac-keyvault ssh-agent` reads selected custody records and enables
private signing; it is never an agent step. Inert owner syntax:

```text
mac-keyvault ssh-agent --socket /absolute/private-run/agent.sock --key selected-service/auth@1
```

`--socket` requires an owned private 0700 directory and a new socket path.
Each repeatable `--key` is `service/purpose@VERSION` with an explicit positive
generation; 1–32 keys are accepted. Policy and public-key validity are checked
at startup and private policy is rechecked for signatures. Duplicate public
identities refuse. The bridge exposes listed identities and signing, not
add/remove-key, arbitrary extension or general private-key export operations.

## Confirmation, duration and signing scope

| Flag | Boundary |
| --- | --- |
| `--confirm-exec /absolute/executable` | Fixed executable, no shell; exit 0 grants, all other outcomes refuse |
| `--confirm-arg ARG` | Repeatable literal argument to that executable |
| `--confirm-timeout DURATION` | Default 15s; must be positive and at most 1m |
| `--confirm-when sign\|unlock\|both` | Default `sign`; unlock modes require `--unlock-for` |
| `--unlock-for DURATION` | Explicit positive duration at most 24h; wall-clock expiry stops serving |
| `--sign-namespace git` | SSHSIG-only selected namespace; authentication/other data refuse |
| `--audit-log /absolute/file` | Audit opens before socket; successful signatures require audit append |

Confirmation options require `--confirm-exec`. Unlock confirmation happens for
each selected identity before opening the socket. A hook is consent UX, not
hardware presence or per-agent authentication. Owner-presence records retain
their OS prompt requirements even with a hook. `confirm-dialog --wait DURATION`
is the optional human confirmation hook, not a way to automate approval.

Namespace restriction is essential when an intended Git signing socket must
refuse authentication. Keep authentication and Git signing keys/sockets distinct.
A `git` namespace signature is not typed release authorization. Audit covers
requests for selected identities; do not claim immutable or exhaustive host
forensics from a same-user file.

## Integration and failure handling

The owner selects the dedicated socket through SSH `IdentityAgent` for the
intended new host, and uses an independently checked public `IdentityFile`.
Git SSH signing selects its socket separately via `SSH_AUTH_SOCK`. Do not
change global defaults or enable forwarding; any deployment/config change
requires its actual owner route. This skill supplies no launch job or installer.

A denied/unavailable prompt or failed confirmation ends that attempt. Do not
restart a headless job in a loop or alter ACLs. Remove a stale socket only after
the owner establishes no live agent owns it. Same-user socket access does not
identify a particular model/agent. Source synthetic OpenSSH/Git tests do not
prove live host authentication, provider registration or installed ACL approval.
