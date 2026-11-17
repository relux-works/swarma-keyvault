# Nostr secp256k1 custody

## agent-nostr policy

### Requirements-owner scope

The requirements-owner rule is limited to manager-only issuance and enrollment,
plus signing and public reconciliation by an enrolled agent for its own exact
full identity, service and generation. This is trusted-actor operating policy
on a shared OS user. It neither authenticates a principal from CLI input nor
isolates against a hostile process with the same user authority. The CLI does
not issue a2a grants or provision identities; actor admission remains in the
existing authoritative operator assignment and issuing-manager workflow. Before
unattended issuance, that workflow must already contain the one-time owner or
delegation authorization; generating a Nostr key does not supply it.

Only the admitted issuing manager may run `generate`, establish the external
enrollment receipt, `list` this namespace, or reconcile an incomplete first
issuance. A conforming enrolled agent may run `sign` and limited `describe` or
`pub` reconciliation only for its own enrolled full identity, service and
explicit generation. The `--identity` value and receipt path are required
consistency inputs; neither authenticates the caller. This policy does not
permit direct Keychain or Enclave inspection, other command families, owner
keys, private export or unwrap, trust edits, OS prompts, or arbitrary helper
invocation.

The issuing manager keeps the public enrollment receipt in its existing
admitted custody and establishes the exact full-identity to service, version
and public-pin mapping in the canonical `agent-nostr-enrollment/1` format. The
full identity comes from the authoritative operator source and is preserved
exactly; this family adds no identity validator. The agent receives the receipt
locator through its admitted assignment route. File ownership or permissions
do not authenticate that receipt against a hostile same-user process. A vault
row, display alias, service string or environment value cannot establish
enrollment. There is no automatic
adoption, rebinding, newest-key selection, overwrite, retry, deletion or
rotation fallback. A new version or changed mapping requires a manager's
explicit recorded enrollment. If first-issuance output or receipt recording is
lost, issuance stays unresolved: a row alone does not prove it is the issued
key, and no replacement is created. An already-enrolled agent may reconcile
only its pinned own generation.

The closed command family has exactly these operations (syntax only; these
examples do not grant authority):

```sh
mac-keyvault agent-nostr generate --service agent-NAME --version N
mac-keyvault agent-nostr list
mac-keyvault agent-nostr describe agent-NAME/nostr --version N
mac-keyvault agent-nostr pub agent-NAME/nostr --version N --format x-only-hex
mac-keyvault agent-nostr sign agent-NAME/nostr --version N --identity FULL_MXID --enrollment-receipt PATH --digest HEX
```

No implicit version, newest-key selection, rotation, deletion, seed or private
export is part of this family. `describe`, `pub` and `list` are vault-backed
commands, not offline inspection. Internal backend access by the signed tool
does not grant an operator direct store access.

Live use requires landed reviewed source, canonical skill adoption with exact
runtime readback, and a qualified matched vault/helper pair. This source
reference alone does not install or adopt the policy. Native custody and
matched-pair qualification remain `REQUIRED_NOT_RUN` until their separate
admitted lane passes.

### Dated owner words

The requirements-owner scope above is the rule; these dated words are quoted
separately and do not expand that scope:

2026-11-16, about 14:29-14:35Z:

> «посмотри записи чо мы хотели в а2а и чо не хватает чтоб не создавать хуеву тучу записей руками но рпи этом чтоб у каждого агента точно была своя пара ключей против его идентики»

> «ну да наверн я те должен буду выдать один раз по тач айди и дальше вы сами»

2026-11-17, about 08:23Z, on Namecoin names with keyvault keys:

> «пусть ваня решает я тут уже не секу как лучше, делайте как ваня скажет по неймкойну, нужны ключи даваяй выпустим»

## Legacy Nostr custody

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
