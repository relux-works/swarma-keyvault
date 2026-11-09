# Nostr keys on macOS

`mac-keyvault nostr` provides dedicated secp256k1 keys and BIP-340 Schnorr
signatures for 32-byte NIP-01 event ids. It does not change P-256 records,
signer contract 1, SSH-agent signing or the KEK interfaces.

## Custody

Generation samples a nonzero scalar below the secp256k1 group order from the
OS cryptographic random source. The scalar is stored as the encrypted value of
a generic-password item in the OS account's login Keychain, selected by its
explicit path rather than the default search list or `HOME`. The dedicated
service is `works.relux.mac-keyvault.nostr.v1`; the account is
`SERVICE/PURPOSE@VERSION`. An atomic add refuses an existing account.

The item is created with a `SecAccess` trusted-application list containing only
the signed vault executable. Generation and private use verify the executable's
code signature. Every native operation disables Keychain UI. Locked Keychain,
wrong code identity, unreadable item and denied access fail without a prompt,
fallback, replacement or expansion of trust. Before private use the backend
also refuses missing or broadened decrypt ACLs. Native enforcement must be
qualified against the actual installed code signature and macOS version.

This is software custody: records explicitly report `storage=keychain-acl`,
`presence=false` and `private_export=false`. No hardware non-extractability or
per-signature Touch ID is claimed. The scalar exists transiently in the vault
process during generation/signing. Explicit owned byte buffers and private-key
objects are cleared on success and refusal. Go, the cryptography library and
Security.framework can retain internal copies outside those explicit buffers;
this is not a guarantee against memory inspection, crash dumps or an owner/
administrator changing Keychain access. Protect the Mac and its login account.

No command imports or exports private scalars, seeds or `nsec`. There is no
private-key getter in the backend interface. Public queries request attributes
only, without fetching the encrypted secret value. Public metadata is not an
independent attestation: retain the public key obtained at attended creation
and use that independent pin when verifying signatures.

The canonical `nostr-key/1` record binds service, purpose, generation, creation
time, algorithm, storage/presence/export policy and both public encodings.
Unknown/duplicate fields, noncanonical metadata, mismatched account, invalid
public point or inconsistent `npub` refuse. Signing compares the scalar's
derived public key to that record and verifies the signature before output.

## CLI

These are syntax examples for an authorized sitting, not requests to create or
use a live key. `example` is a placeholder service. Generation defaults to
version 1; public/private operations select version 1 unless `--version N` is
explicit. There is no implicit newest-generation selection, rotation or deletion.

```sh
mac-keyvault --json nostr generate --service example --purpose nostr --version 1
mac-keyvault --json nostr list
mac-keyvault --json nostr describe example/nostr --version 1
mac-keyvault nostr pub example/nostr --version 1 --format x-only-hex
mac-keyvault nostr pub example/nostr --version 1 --format npub
mac-keyvault nostr sign example/nostr --version 1 --digest HEX_EVENT_ID
mac-keyvault nostr verify --pub HEX_PUBLIC_KEY --digest HEX_EVENT_ID --sig HEX_SIGNATURE
```

The x-only public encoding is 32 bytes as 64 lowercase hex characters. `npub`
uses NIP-19's original bech32 checksum. Sign accepts exactly 64 hexadecimal
characters denoting a 32-byte digest; it does not hash input again. It returns
the 64-byte BIP-340 signature as 128 lowercase hex characters and uses fresh
32-byte auxiliary randomness. It does not publish events or check their NIP-01
serialization: the caller must compute the correct event id. No `--stdin`,
`--data-file`, `--out`, import, export, private format or store selector is
accepted by this command family. Offline `nostr verify` accesses no vault.

`--json` retains the existing `{ok, command, result|error}` envelope and exit
classes: 0 success, 1 operational failure, 2 invalid CLI arguments, 3 policy
refusal. Refusals contain controlled codes, never private material. On an
interrupted creation or lost output, inspect the public record: retry cannot
overwrite it or create another key under the same account. A failed sign never
generates a replacement key.

## Validation and adoption

From the repository root:

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 scripts/keyvault-test-confined.sh ./internal/keyvault ./cmd/mac-keyvault -run '^TestNostr' -count=1
MAC_KEYVAULT_SKIP_KEYCHAIN=1 scripts/keyvault-test-confined.sh ./... -race -count=1
```

The public [official BIP-340 fixtures](../internal/keyvault/testdata/nostr/README.md)
cover all 19 published rows. Four newer variable-length message rows explicitly
refuse this digest-only API; the specification itself supports those lengths.
Tests pair valid controls with wrong-key, malformed digest/signature, invalid
scalar, entropy failure, corrupt metadata, missing item, backend refusal,
duplicate and interrupted-output cases. Confined fake-backed tests prove policy,
crypto interoperability and public output boundaries; they do not prove native
Keychain ACL enforcement, persistence or installed adoption.

Before live creation, qualify the reviewed signed executable at one planned
owner sitting: exact build/signature, dedicated test-item create/public/sign,
locked-store refusal, wrong/rebuilt executable refusal with UI disabled,
ACL readback with exactly one trusted executable, duplicate retry and missing/
mismatched record refusal. Do not lock the owner's working login Keychain just
to manufacture a test; use an explicitly admitted isolated fixture or leave that
native case unverified. Preserve unrelated records and existing binary trust.

Installation or a changed executable signature requires a planned custody
adoption; never replace a trusted executable or broaden an ACL to repair a
refusal automatically. Generate the owner's actual identity only after the
candidate is accepted and the sitting admits installation/qualification. Share
only its x-only public key and `npub`. Secure Enclave wrapping with presence
would require a separate key-agreement/helper contract; it is not an alternate
backend or fallback in this implementation.

References: [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md),
[Apple SecAccess](https://developer.apple.com/documentation/security/secaccesscreate(_:_:_:)).
