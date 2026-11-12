# Public Namecoin Core fixtures

These are public, disposable Namecoin Core28 registration graphs and signature
fixtures derived from the published BIP32 test-vector-1 account. Both release
modes contain A/B reservations and C/D reveals. The account pin and every
opening, identity and name value are synthetic. Signed PSBT and finalized
transaction bytes are independent Core outputs, not protected-custody receipts.
Request/review/result format examples live in `internal/namecoinwire/testdata`.

The compatibility examples cover optional matching witness UTXO and explicit
SIGHASH_ALL forms, plus intentional rejected forms. Tests also construct a
matching optional global xpub and a witness-bearing full previous transaction.
Those source-generated controls are labelled separately from Core output.

The transaction hashes follow [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki),
maps follow [PSBTv0](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki),
and public/private child arithmetic follows [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
Namecoin script behavior is grounded in the
[Core28 name-script implementation](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/script/names.cpp).
No live key, recovery phrase, owner account, node state or grant authority is
present. Public signature verification does not establish native review,
biometry, protected journal provenance or permission to broadcast.
