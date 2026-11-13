# Public root grants derivation fixtures

These tests use published test authorities only. They never accept an owner's
mnemonic or invoke the native helper, Keychain, wrapping, presence or signing.
These tests cover fixed root grants derivation and attachment preparation; they do
not establish a usable creation/export command or native qualification.

The fixed product profile is `namecoin-landlord-root/1`, derivation
`bip85-hdseed-wif/1`, path **`m/83696968h/2h/7h`**. Application2/index0 below is
an official primitive fixture only. There is no product path/index parameter,
WIF serializer, private export or generic signing operation.

## Published anchors

| Source | Exact pin and use |
| --- | --- |
| [BIP85 v2.1.0](https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0085.mediawiki) | SHA256 `dcbeb97709eba4751f4af7dc582c35dff37dc831abb5adc5e2e975d708d1cf7e`. Specification lines52–62 and general vectors64–82 pin both child scalars and all64 entropy bytes. HD-Seed WIF lines226–248 pin application2/index0 first32 entropy bytes and its published compressed WIF payload/checksum. BIP85 offers BSD-2-Clause or OPUBL-1.0; these numeric test expectations select BSD-2-Clause. Authors: Ethan Kosakovsky and Aneesh Karve. |
| [BIP39 official implementation vectors](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json#L52) | SHA256 `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8`. English 256-bit-zero entropy and mnemonic at lines52–53: 23 `abandon` words followed by `art`. Only entropy/mnemonic are used here; its published seed/xprv use `TREZOR` and are NOT empty-passphrase expectations. The product permits the empty passphrase only. The existing English-list/spec pins and MIT attribution are in [README.md](README.md). |
| [BIP32 vectors1–4](https://github.com/bitcoin/bips/blob/d71d60687b4c250ae9c73c1cc29897dbd56e9903/bip-0032.mediawiki) | Existing immutable `bip32-vectors.json` preserves all17 xpub/path expectations, including leading-zero cases. Specification SHA256 `e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f`; attribution/license in [README.md](README.md). Retain `TestRecoveryBIP32PublishedPaths`, `TestRecoveryBIP32MasterVector`, and `TestRecoveryBIP32InvalidChildBoundaries` in the focused lane. |
| [NIP06](https://github.com/nostr-protocol/nips/blob/b587c619c2ea662d40b40976aeccf6ac8d6ba9eb/06.md) | SHA256 `a7d86f43c3723b7a67765e81910a2478007d4655024e2899a163a09e2c834b3a`. Published24-word phrase and social public pin anchor the unchanged empty-passphrase account0 mapping. The existing independently generated `reference-public.json` and frozen v1 public record constrain Namecoin xpub/origin. Their provenance and limits remain in [README.md](README.md). These Namecoin expectations are reference outputs, not NIP06-published Namecoin vectors. |
| [BIP340 row0](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv) | Existing `../nostr/bip340.csv` row0 independently pins scalar3 and x-only K `f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9`. Scalar `n−3` is the algebraic opposite-parity control, not another published row. Both must normalize to scalar3 and the same even-Y compressed point. Existing fixture attribution selects CC0-1.0; see [Nostr fixtures](../nostr/README.md). |

`TestRootGrantsPublishedBIP85` checks exact published bytes before the private
test oracle can be trusted. Its master xprv and WIF strings are intentionally
public fixtures confined to `_test.go`; the product has no import/export path
for those encodings. The full general entropy checks catch reversed HMAC roles,
wrong key spelling, raw child substitution, truncation or serialization mistakes.

`TestRootGrantsFixedIndex7` uses independent test-only `math/big` hardened BIP32
addition, followed by standard HMAC-SHA512. It shares SHA512 and curve arithmetic
with production; the official BIP85/BIP32/BIP340 controls ground those primitives.
The fixed-index public comparison is an algorithmic expectation, **not a
separately published index7 public vector**. The independently generated index7
expectations live in `reference-root-grants.json`, produced by the isolated
`tools/recoveryreference/rootgrants` oracle (unmodified upstream modules, grounded
in the official BIP85 index0, BIP340 and NIP06 vectors) and compared byte for byte
in hosted CI; `recovery_root_grants_reference_test.go` compares the product with
it. The independent integrated review remains required; two implementations
agreeing alone is insufficient.

## Claims and limits

Each test group states its own claim and limits in source. Valid v1 and v2 pair
metadata must pass, including v1 service inheritance and v2 explicit identities.
Every external pair-reference field is mutated independently. Separate valid
records swap just social, account or origin pins while updating the public
record hash; this reaches derived-pin checks rather than testing only hashing.
Valid creation-time and wrapping-point changes retain all projected pins; they
must still fail the full-metadata digest retained from the original record.
Wrong phrase/order/count/checksum/path/record/pin and cancellation before/after
preparation return no handle and clear owned input. Reordered valid English
words may fail checksum or, if checksum-valid, fail public pins.

There is no storage/wrapping effect interface in this seam. That structural
limit does not prove the later caller's no-write ordering, unchanged ciphertext,
ACL, actual `/dev/tty` behavior or fresh Touch ID. Those need integrated
instrumented and native controls before an attended release. Public preparation
does not claim `stored`, native authentication or grant issuance.

Private handle copies share one scalar allocation. Clear invalidates all copies;
formatting is fixed text and JSON serialization refuses. Explicit `clear`/`Zero`
calls cover owned phrase, seed, pair material, BIP32 nodes, entropy and scalar
buffers at their logical boundaries. Go/compiler/runtime and crypto-internal
copies cannot be guaranteed erased; reflection/unsafe is not a security boundary.
Attach retains no chaincode. A future all3 flow must retain the Namecoin account
chaincode through its own sealing; this source adds no all3 behavior.
