# Public Nostr fixtures

`bip340.csv` is the complete official BIP-340 test vector file from
`bitcoin/bips`, commit `200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb`,
[`bip-0340/test-vectors.csv`](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv).
Only line endings are normalized from CRLF to LF; all CSV values are unchanged.
The test scalars and auxiliary randomness in it are deliberately public test
inputs. They are never used for vault custody or real Nostr identities.
The BIP's code and vectors are available under BSD-2-Clause, MIT or CC0-1.0;
this copy selects CC0-1.0.

All 19 rows are accounted for. Rows 0–14 exercise digest signing/verification;
rows 15–18 have variable message lengths and must be refused by this module's
32-byte event-id API. This restriction does not assert those newer signatures
are invalid under the broader BIP-340 specification.

The npub control in `TestNostrNPub` is the public example in
[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md).
