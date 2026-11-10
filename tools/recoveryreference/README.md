# Public recovery reference

This separate Go module reproduces public Nostr and Namecoin account outputs
using unmodified upstream BIP-39 and BIP-32 modules, without the product's local
crypto replacements. It accepts no arguments or user seed input. Every input
is a published NIP-06 phrase or explicitly synthetic public entropy. Output
contains only the fixture phrase and public identities, never private keys.

```sh
go -C tools/recoveryreference mod download
go -C tools/recoveryreference mod verify
go -C tools/recoveryreference test -race -count=1 ./...
go -C tools/recoveryreference run . > .temp/recovery-public.json
cmp .temp/recovery-public.json internal/keyvault/testdata/recovery/reference-public.json
```

Run with the exact Go version in its `go.mod`; `go.sum` pins every module. There
are no `replace` directives. The direct references are
`github.com/tyler-smith/go-bip39 v1.1.0`,
`github.com/btcsuite/btcd/btcutil v1.1.6`,
`github.com/btcsuite/btcd v0.24.2` and
`github.com/btcsuite/btcd/btcec/v2 v2.5.1`.

The two published NIP-06 public keys independently anchor the reference tests.
Product tests compare all five public outputs, including `npub`, the fixed
Namecoin account xpub and master origin. Receive `0/0` and change `1/0` public
children are derived from the public account in the reference and from the
private account in product tests. Official BIP-32 vector paths separately
anchor leading-zero handling. Agreement alone is not proof of correctness.
Hosted CI verifies this module, tests it and requires exact fixture regeneration.
This fixture program performs no native custody, installation or network-node
operation; dependency download is separate from fixture execution.
