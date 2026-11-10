# Multi-use grant workflows

Source: `cmd/swarma-keyvault/mu*.go`, `internal/mugrant/`,
`internal/grants/mu_service.go`, `mu_platform.go`, `mu_receiver.go` and
`mu_state.go`. These implement `swarm-envelope/2` records; old local/a2a
certificate envelopes are not interchangeable. All syntax below is inert.

## Public preparation and OWNER-SITTING issuance

Commands follow `swarma-keyvault grants`. Preparation never signs or creates
custody keys; grant/request preparation draws a fresh nonce, so repeating it
can change the body/content ID/digest. Do not claim two preparations are the
same signed operation.

| Command | Actual input flags |
| --- | --- |
| `mu-key-id` | `--subject-spki-der FILE`; P-256 SPKI to platform key ID |
| `mu-attestation-prepare` | `--spec FILE --subject-spki-der FILE` |
| `mu-grant-prepare` | `--spec FILE --subject-attestation FILE --publisher-attestation FILE` |
| `mu-request-prepare` | `--spec FILE`; prepares `message/1`, exact visible text and digest |
| `mu-root-revocation-prepare` | `--spec FILE`; prepares `revocation/1`, no signature |
| `mu-assemble` | `--kind grant/1\|message/1\|attestation/1\|revocation/1 --body FILE --key KEY_ID --signature DER_FILE`; checks/assembles supplied native P-256 signature |

Spec files use exact UTC whole-second `YYYY-MM-DDTHH:MM:SSZ`. Prepared output
includes canonical body's unpadded base64url, content ID and signing digest;
decode `body` for `--body`, do not pass the prepared JSON or base64 text.
Assembly uses the prepared body/key/kind and verifies the signature. It does not
supply enrollment, install an attestation or publish a record. `mu-assemble`
and `mu-key-id` are P-256 CLI routes; Ed25519 library support does not add an
Ed25519 signing CLI. For an Ed25519 library workflow, sign the exact
`Plan.Preimage()` directly rather than its SHA-256 digest; the algorithms do not
share a signing-input contract.

**OWNER-SITTING:** `mu-issue --kind KIND --spec FILE --owner-spki-der FILE --owner-key SERVICE/grants-owner-v1 --owner-key-version N`
accepts `grant`, `mac-agent`, `publisher`, `publisher-ed25519`.
For `grant` add both `--subject-attestation` and `--publisher-attestation`;
for the three attestation kinds add only `--subject-spki-der`.
The signer uses the independently configured `SERVICE/grants-owner-v1` and exact generation: exact public
pin, Enclave, presence, extraction `none`. The typed body/reason are prepared
before manager construction; full rendering is written just before the private
call, and the native signature is checked before output. No retry, creation or
store fallback follows a failure. `mu-issue` has no root-revocation kind.

Mac-agent attestations bind key/full MXID/generation with `mac-se-1`.
Publisher attestations bind either P-256 `grant-revocation-1` or Ed25519
`grant-revocation-2`; owner root remains P-256 for both. An Ed25519 publisher
attestation does not create or operate its signing service. Grant preparation
in this CLI requires the exact owner-root Mac subject and publisher attestations, matching
identity/window and distinct roles. Uses are `once` or `until_expiry`, never a
license to create, widen or delegate grants. Message lifetime is at most 120s;
text is separately constrained to the same admissibility rule at both ends.

## Publisher: admitted service, never an agent step

Actual `mu-revocation-publish` flags are `--publisher KEY_ID --signer S/P
--keyvault PATH --keyvault-sha256 HEX --entries FILE --out FILE --interval DURATION`
with optional `--once`. Interval is required even with `--once` and must be
1–60 seconds; `--out` is absolute. Each cycle builds a complete snapshot,
checks the pinned executable, invokes its P-256 `sign` with a 20s context,
assembles/verifies, then atomically replaces a private output file. On failure
before replacement it keeps the previous snapshot; a status-output failure can
occur after replacement. The child receives no generation flag: ordinary `sign S/P` selects the newest
generation, while assembly verifies against `--publisher`. Do not assume a
persistent generation pin. The ongoing loop can retry failed cycles, so this is
not an OWNER-SITTING one-shot owner signature route.

Provision/adoption belongs to the owner; running this signing loop is never an
agent diagnostic step. The CLI does not expose Ed25519 publisher-service
signing. Receivers need fresh verified publisher snapshots (at most 60s) and
retained monotone revocation knowledge; removing an entry cannot un-revoke it.
Do not label local host-time assertions as a protected clock implementation.

## Receive and root revocation

`mu-state-init --config FILE` explicitly initializes an empty private state
directory. `mu-execute --config FILE --event EVENT` projects the original event,
verifies it again, locks/rechecks local scope/revocation, reserves, syncs intent,
executes the configured effect and records outcome. Both are mutations or
external-operation routes, not offline inspection commands. Configuration is
`mu-receiver-config-1`: admitted owner/root, audience, grants/agents/publisher,
root revocations, state epoch, room/modules/pause/registry ownership, own a2a
projection and task-board pins. Production service rejects `test:` audiences.
Its configured effect map contains only `work.assign` via pinned TaskBoardAssign;
a vocabulary entry is not a configured effect provider.

UNKNOWN retains holds; preserve state and do not replay/reset. Owner-scope
checks reject grant-authority widening and out-of-scope product/account/room
requests. Host files/locks/epochs do not prevent coherent same-UID rollback.

Root revocation is a separate **OWNER-SITTING** flow: public
`mu-root-revocation-prepare` requires a nonempty entries list; owner reviews its
exact rendering/digest, signs under the admitted root-presence route, and
`mu-assemble --kind revocation/1` binds the signature. There is no dedicated
`mu-root-revocation-issue`/install CLI. The custodian supplies authenticated root
revocations out of band in protected receiver configuration, never through the
publisher. Verified root revocations win at any age and remain separate from
publisher freshness marks; this does not authorize an agent to edit runtime
configuration. Keep the exact prepared body and digest; generic signing never
replaces the required typed review.

## Library support and qualification limits

`LinuxVerifier`/`LinuxReceiver` and Keymaker evidence adapters are implemented
library components, distinct from the Mac-agent `ParseMUService` CLI composition.
They require protected identity/generation, time/assurance and distinct service,
agent-revocation, publisher and owner roots. The CLI config does not expose the
full Linux evidence/receiver composition. `docs/linux-receiver.md` describes
per-signer durable unions/marks and refusal ordering. No live transport, protected
clock, custody/signing service or deployed effect provider is supplied by that
library. Interop vectors prove only source test scenarios when actually run.
Future general certificate APIs, plugin selection and release-signing services
are not established by these implemented boundaries.
