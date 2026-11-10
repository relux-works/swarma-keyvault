# Application-key a2a grants

Source: `cmd/swarma-keyvault/a2a.go`, `internal/grants/a2a_certificate.go`,
`a2a_request.go`, `a2a_executor.go`, `a2a_observation.go`, `a2a_state.go` and
`internal/grantissuer/repository.go`. This is a separate profile from
[local grants](grants.md) and [multi-use envelopes](multi-use.md).

## Authoring and OWNER-SITTING signing

All names below follow `swarma-keyvault grants`; syntax is inert.

| Command | Actual flags / role |
| --- | --- |
| `a2a-prepare` | `--payload FILE\|- --owner-spki-der FILE --requester-spki-der FILE --owner-mxid MXID --owner-key SERVICE/grants-owner-v1 --owner-key-version N`; unchanged checked payload and full review, no private call |
| `a2a-issue` | Same flags; OWNER-SITTING typed owner signing, no enrollment/activation |
| `a2a-request-prepare` | `--payload FILE\|- --request FILE`; prepares the request and exact domain digest |
| `a2a-request-pack` | Same plus `--signature FILE --public-spki-der FILE`; validates supplied DER signature, does not sign |
| `a2a-verify` | `--config FILE --event EVENT`; network projection plus public verification, no execution-state open/provider call |
| `a2a-state-init` | `--config FILE`; explicit state creation in an existing empty private directory |
| `a2a-execute` | `--config FILE --event EVENT`; original-event projection, durable reservation and provider effect |

The bounded certificate is `grants-a2a-certificate-1`: full grantee MXID and
P-256 SPKI hash, one private CREATE of
`relux-works/matrix-grants-g2-261104`, one use, interval at most 30 minutes, no
DELETE. Issuance uses the explicit owner principal and exact configured key with the independent pin/presence policy of the typed
issuer. Its action/target/full-grantee/key/window/domain-digest reason is
bounded to 200 Unicode scalars and never truncated. Actual OS display coverage
is not established by that limit.

The signed request has twelve closed string fields; the separate action payload
is `name`, `organization`, `visibility`. Preserve canonical ASCII JSON and
unpadded base64url exactly. Request lifetime is at most five minutes.
Preparation's `digest_sha256` includes `swarma-grants/a2a-request/1` plus LF and
exact payload bytes. A separately authorized OWNER-SITTING request signature
uses the admitted digest once; do not hash the digest again. Packing a supplied
signature proves its relationship to the supplied key, not receiver trust.

## Verification is not offline local verification

`a2a-verify` executes the configured pinned projection binary and observes a
network event. It is not an inert alternative to local `grants verify` and is
not an agent step in a static-only task. There is no projection-file/stdin
bypass. Protected config selects exact owner/public registries, receiver,
room/thread/topic, own a2a identity/config root, epoch and executable pins.
Never supply another identity's credential directory.

The executor calls the admitted a2a interface with
`--profile CONNECTION --as IDENTITY read ROOM --event EVENT --verification-input --json`
and configured `A2A_CONFIG_DIR`. It requires successful bounded process output:
exactly one JSON observation plus LF and matching original event/sender/receiver
and configured context. Absent returned-room evidence is weaker endpoint-only
context, not a proved returned-room match. Human labels and wrappers do not
substitute for full identity, signature or authentic projection provenance.

Config loading admits a regular non-symlink current-user/root-owned file,
not group/other writable; it is a separately installed trust root, not request
input. Executables additionally require an absolute clean path, executable
regular file and exact SHA-256. Same-UID replacement races remain outside these
checks. Actual live projection/provider qualification is not claimed.

## State and uncertain effects

`a2a-state-init` creates state and `a2a-execute` runs the provider effect;
neither is an agent step without the custodian's authorization for that
exact state or event. State init is separate. Execute opens existing state
only and never repairs,
migrates or creates a replacement journal. Keep epoch/state across registry
refreshes. Nonce and grant-use indexes are independent: a new registry/grant
cannot refill a used grant or replay an old nonce. Preserve UNKNOWN and failed
publication after dispatch; no automatic retry, release, DELETE or journal reset.
Public signature verification alone does not reserve or authorize an effect.
