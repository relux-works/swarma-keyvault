# Nostr secp256k1 custody

`mac-keyvault nostr` is a separate command family: `generate`, `list`,
`describe`, `pub`, `sign`, exact `delete` and offline `verify`. It does not extend P-256
signer contract 1 or SSH-agent signing. Public formats are `x-only-hex` and
NIP-19 `npub`; signing takes only a 32-byte event id via `--digest HEX`
and returns a 64-byte BIP-340 signature. The caller computes the NIP-01 id.

Legacy random-key generation stores the secret in a dedicated login-Keychain item whose ACL trusts only the
signed vault executable. Records state `storage=keychain-acl`, `presence=false`,
`private_export=false`. The scalar exists transiently in the vault process;
this is neither Secure Enclave custody nor hardware non-extractability.
Explicit buffers are cleared, but Go/library copies cannot all be guaranteed
erased. This family has no private import/export, `nsec`, seed output or store
fallback. The separate [recovery family](recovery.md) derives a NIP-06 leaf and
Namecoin account from one attended mnemonic backup. Its Nostr projection reports
`storage=enclave-wrapped-keychain`, with no presence requirement. Public queries
and signing distinguish both explicit storage forms.

All live creation, vault-backed inspection and signing retain the main skill's
OWNER-SITTING boundary. A lack of Touch ID does not authorize autonomous use.
Installation and changed-binary trust adoption belong to that planned sitting;
never replace an installed trusted executable or widen an ACL to recover.

Version defaults to 1 for generation and selection. Select another explicitly
with `--version N`; there is no implicit newest-key selection or rotation.
Deletion requires an explicit version plus `--expected-npub`, and refuses a
recovery projection: the paired group has a separate exact deletion operation.
Malformed digests, noncanonical/corrupt metadata, duplicate accounts, key
mismatches, locked Keychain and untrusted executables refuse. A failed/lost
creation result can follow an atomic add: inspect the public record rather
than create a replacement. Public reads request metadata only; offline verify
never constructs a vault backend. Retain an independent public pin.

Example syntax only, for the selected owner sitting:

```sh
mac-keyvault --json nostr generate --service example --purpose nostr --version 1
mac-keyvault nostr pub example/nostr --version 1 --format x-only-hex
mac-keyvault nostr pub example/nostr --version 1 --format npub
mac-keyvault nostr sign example/nostr --version 1 --digest HEX_EVENT_ID
mac-keyvault nostr verify --pub HEX_PUBLIC_KEY --digest HEX_EVENT_ID --sig HEX_SIGNATURE
```

Source evidence: `cmd/mac-keyvault/nostr.go`, `internal/keyvault/nostr.go`,
the native bridge and `docs/nostr.md`. Fake-backed vector/refusal tests are
distinct from attended native ACL/persistence and actual installation checks.
