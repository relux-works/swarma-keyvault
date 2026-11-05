# Integrating a service with kek-1

Read [the full contract](kek.md) before provisioning. The supported public import
is `github.com/relux-works/swarma-keyvault/pkg/kekclient`; select an exact reviewed
revision through the service's existing Go dependency flow. Existing consumers
retain their accepted dependency until their own adoption is qualified. Old and
new module packages have distinct types and sentinel errors; use `errors.Is`
with the sentinel from the module actually producing the error.

## Configure before provisioning

Select the absolute reviewed broker path, an existing real current-user-owned
private socket directory and a positive exchange timeout. There is no plugin
registry or global keyvault configuration selector in this extraction. Feed these
values through the consuming application's actual configuration; do not invent a
shared provider or plugin API.

This minimal Go fragment performs only metadata preflight:

```go
opts := kekclient.Options{
    Broker:    "/absolute/reviewed/mac-keyvault-kek",
    SocketDir: "/absolute/private/service-run",
    Timeout:   30 * time.Second,
}
if err := kekclient.Preflight(opts); err != nil {
    return err // Map to a controlled service error before displaying it.
}
```

The fragment assumes imports of `time` and the supported `kekclient` package,
and a surrounding function returning `error`. It does not create directories,
draw a nonce, start a broker, access a key or prove caller admission. A selected
directory symlink, unsuitable ownership/permissions or generated socket path
over 103 UTF-8 bytes is refused. `ErrSocketPathTooLong` identifies the budget
case. Exchanges repeat preflight, so this observation is not a filesystem lock.

## Provision and use through the service boundary

Onboarding requires an explicit provisioning window, a real selected address
and generation, and public SPKI/fingerprint obtained through the trusted operator
route. Verify that pin independently before wrapping a fresh service KEK. Keep
the envelope and authenticated encrypted store in the service's private storage.
Do not add a plaintext key file, seed export, debug CLI or environment switch.
An existing store is never replaced by an empty one after an unwrap failure.

`Wrap` uses public key material; `Unwrap(ctx, opts, envelope)` starts the broker
and returns private KEK bytes only after its checks. Call it inside the service
process that actually satisfies the envelope's code requirement, not in a
generic diagnostic executable. Do not print the result or broker stderr. Check
the service's authenticated store before continuing; clear owned transient KEK
buffers when finished, without claiming runtime/kernel copies are erased.

Choose exactly one admitted binding form: canonical lowercase CDHash, or the
complete leaf-certificate DER's SHA-1 plus exact signed identifier. Use the
package constructors and independently supplied facts. A certificate subject,
filename or Team ID is not a substitute. Certificate mode requires a qualified
supporting client/broker pair; it has no default certificate.

For CDHash upgrades, only the currently bound old service can request `Rebind`
to the validated new file at the envelope's retained install path. The response
is a replacement envelope, never a KEK; persistence belongs to the service's
qualified update flow. Certificate mode refuses rebind and never changes pins
or converts modes. Certificate rotation requires explicit reprovisioning.

## Conformance pairs

Ground acceptance in the full contract and consuming store's invariants:

| Positive control | Required refusal / preserved state |
| --- | --- |
| Real private directory and generated socket path within 103 bytes | Symlink, bad ownership/permissions or over-budget path: no broker/provisioning effects |
| Valid envelope and exact bound hardened caller | Foreign/injectable caller or altered header/ciphertext: no KEK |
| Valid current key with `decrypt` usage | Missing/expired/unreadable key or wrong usage: no KEK and no replacement key |
| Audit append and sync succeeds | Audit failure: no successful answer |
| Authenticated store accepts the unwrapped key | Chosen substitute KEK or unreadable store: stop, no empty store |
| CDHash rebind from the old bound service to a valid new target | Unbound caller, invalid/same target or certificate mode: no replacement envelope or KEK |

Fake-backed protocol tests, native public-code checks and actual installed
service-pair tests are separate evidence. A confined trust refusal cannot count
as native certificate-match success. See [validation](validation-recovery.md).
