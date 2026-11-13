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

## Index-7 root grants oracle

`rootgrants/` is a second program in this module. It is the independent
expected-value oracle for the fixed root grants key (BIP85 application 2, path
`m/83696968h/2h/7h`, HMAC key `bip-entropy-from-k`, first 32 entropy bytes,
even-Y normalization). It takes no arguments, shares no code or constant with
the product's derivation, and emits only public values for four 24-word public
phrases (the published NIP-06 phrase and three synthetic public entropies):
x-only K, `02||K`, the P2PKH seal script and the pre-normalization Y parity.

```sh
go -C tools/recoveryreference run ./rootgrants > .temp/root-grants-reference.json
cmp .temp/root-grants-reference.json internal/keyvault/testdata/recovery/reference-root-grants.json
```

The committed `reference-root-grants.json` is compared byte for byte in hosted
CI, which also plants a one-byte change to show that the comparison detects
drift. The product test reads that file; the expected K is never produced from,
or copied out of, the product. Grounding: the oracle's own transform reproduces
the official BIP85 general vectors and the HD-Seed WIF application 2 / index 0
entropy and WIF string; BIP340 rows 0-3 and the opposite-parity scalar `n-3`
ground the secret-to-key and normalization step; the NIP-06 published keys
ground phrase-to-master. Wrong-HMAC-key, raw-child, last-32-bytes and wrong-index
plants must disagree with those same anchors. The index-7 values were also
cross-computed once by a separate one-off stdlib-only Python derivation that
passed the same anchors; those values are pinned in `rootgrants/oracle_test.go`
so that regenerating the fixture from a changed oracle cannot silently move
them. Limit: index 7 itself has no published vector, and the four phrases are
public test inputs, not a proof for arbitrary seeds.
