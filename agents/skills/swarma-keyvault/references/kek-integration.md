# Integrating a service with kek-1

Source: `pkg/kekclient/client.go`, `preflight.go`, `envelope.go`, `strict.go`
and the [broker boundaries](kek.md). The public import is
`github.com/relux-works/swarma-keyvault/pkg/kekclient`. Select its exact reviewed
revision through the consumer's existing dependency flow; installing a skill
does not repin a consumer. Different module imports have distinct Go type and
sentinel identities; use `errors.Is` against the producing package's sentinel.

## Public preparation versus private operation

`Options` contains `Broker` (absolute reviewed broker path), `SocketDir`
(existing private current-user-owned directory), `Timeout` (zero defaults to
30 seconds). Select a positive exchange deadline for the consumer. Metadata-only
`Preflight(opts)` creates no
process, file, socket or nonce and accesses no key. It is an observation, not
a filesystem lock or caller-admission proof. Every exchange repeats it.

The selected directory must be real, clean and absolute, with no group/other
permissions; a final directory symlink refuses. Generated
`kek-<16 hex>.sock` must fit 103 UTF-8 bytes. A budget refusal satisfies
`errors.Is(err, kekclient.ErrSocketPathTooLong)`. Map other errors to controlled
classes before displaying them: raw errors/broker stderr can contain paths.

`Wrap(WrapSpec, kek)` uses public key material but handles secret KEK bytes;
public-key encryption does not make provisioning agent-safe. OWNER-SITTING
provisioning selects exact address/generation and a separately trusted public
SPKI fingerprint in a recorded window. Keep the envelope and authenticated
store in service-private storage. No plaintext export, seed file or diagnostic
switch may expose the KEK or decrypted store.

`Unwrap(ctx, opts, envelope)` starts the broker and returns the 32-byte KEK only
after protocol and KCV checks. This is private service operation, never an
agent diagnostic step. Call it in the admitted service satisfying the sealed
code requirement. Clear owned transient buffers; runtime/kernel copies are not
claimed erased. Always check the service's authenticated store before proceeding.
A same-user rewrite of both broker and envelope can substitute a chosen KEK;
the original store must reject it and stop.

## Binding and upgrades

Use the constructors for exactly one binding: `RequirementForCDHash`, or
`RequirementForCertificate(identifier, certificateSHA1)`. Certificate pin means
SHA-1 of the complete leaf DER plus exact signed identifier, not subject/Team ID.
No certificate is a default. Qualify the client/broker pair before that mode.

Only the currently bound old service may request CDHash `Rebind` to the validated
new code at the envelope's install path. It returns a replacement envelope,
never the KEK; service update logic owns persistence. Certificate mode refuses
rebind and never converts mode or changes pins. Reprovisioning is an explicit
OWNER-SITTING decision, not recovery from a failure.

On unwrap/protocol/audit/store failure stop the service, retaining the envelope
and encrypted store. Never generate a replacement KEK or start an empty store
as fallback. See [recovery](validation-recovery.md).
