# Public recovery fixtures

All material here is published or synthetic test data. Never put an actual
user's mnemonic, private key, device blob or Keychain value here.

`bip32-vectors.json` preserves all 17 public xpub/path expectations from BIP-32
vectors 1–4, including both leading-zero vectors. It omits private extended
keys. Source:
[`bip-0032.mediawiki`](https://github.com/bitcoin/bips/blob/d71d60687b4c250ae9c73c1cc29897dbd56e9903/bip-0032.mediawiki),
SHA-256 `e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f`.
BIP-32 declares the BSD-2-Clause license and lists Pieter Wuille as author.

`reference-public.json` is reproduced exactly by the isolated
[`recoveryreference`](../../../../tools/recoveryreference/README.md) module.
Its first two inputs are the published NIP-06 rows; the others use zero, all-FF
and sequential 256-bit synthetic entropy. The 12-word NIP-06 row is admitted
only by low-level derivation, paired with product CLI refusal of 12 words.
Source:
[`06.md`](https://github.com/nostr-protocol/nips/blob/b587c619c2ea662d40b40976aeccf6ac8d6ba9eb/06.md),
SHA-256 `a7d86f43c3723b7a67765e81910a2478007d4655024e2899a163a09e2c834b3a`.

The production English list lives in `../../recoverydata/english.txt` and is
embedded verbatim. Source:
[`english.txt`](https://github.com/bitcoin/bips/blob/d71d60687b4c250ae9c73c1cc29897dbd56e9903/bip-0039/english.txt),
SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
BIP-39 declares the MIT license and lists Marek Palatinus, Pavol Rusnak,
Aaron Voisine and Sean Bowe as authors. Specification:
[`bip-0039.mediawiki`](https://github.com/bitcoin/bips/blob/d71d60687b4c250ae9c73c1cc29897dbd56e9903/bip-0039.mediawiki),
SHA-256 `afcbcbed36fe9eb734bd607398a8c124683ded2a75c3830e1b16c47b043a9134`.
The list hash and published derivation results are executable assertions.

`helper/` is a Go subprocess fixture using only framed synthetic bytes. It
never imports custody code or handles actual private material. Its malformed
responses, timeout and request marker exercise private-pipe admission/refusal.
Code-signing controls use copies of this public fixture, including intentional
missing-runtime, wrong-hash and debug-entitlement plants.
