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

The portable canonical-result witness runs with
`go test -count=1 -v ./internal/namecoinpsbt -run '^TestF4'`. Optionally set
`NAMECOIN_F4_RECEIPT` to a path in an existing private scratch directory. It
writes a numeric JSON measurement receipt there, plus `.request.json`,
`.result.json` and `.pin.json` containing the largest generated public fixture.
No generated large fixture is committed. The test does not invoke a signer,
node, native helper, wallet or private key generation.

The matrix covers both release modes and A–D, all independent optional
xpub/version/sighash/witness-UTXO combinations, and every selected previous
transaction as the witness-growth location. All 576 combinations execute with
bounded witnesses; 24 minimum/maximum optional-map cases also reach exactly
1048576 unsigned PSBT bytes with raw requests within 2097152 bytes. The exact
partial-signature insertion ledger makes the maximum result length independent
of intermediate optional maps at that same unsigned cap. Original stripped
previous transactions and published Core signatures stay unchanged, and every
finalized transaction must equal the independent frozen Core output.
Witness item/count CompactSize transitions, maximum legal identity widths,
receipt/sequence widths, original maps, signatures, final transaction sizes,
fees and exact canonical JSON plus LF are accounted for. Joint-budget tests
reach the request cap with space/tab/CRLF manifest whitespace and exhibit the
unreachable combination of independent maximum manifest and PSBT sizes.

The largest measured public-format family and a conservative serialization
upper bound are distinct. The latter uses two maximum-length strict low-S DER
signatures and the entire uint64 sequence width, even though completed journal
history has a tighter sequence bound. It covers all structurally admitted
one/two-input producer shapes through the unsigned PSBT length bound, without
claiming every combination of DER lengths, funding dimensions or journal state
was reached. New stripped funding bodies (including 128-input/output funding),
new signing transactions, other networks, native result generation, journal
completion/reachability and native timing are unverified by this witness.

The separate 6291455/6291456/6291457-byte consumer fixtures contain a real valid
signed result with accepted outer whitespace and freshly computed exact ACK
hashes. They are not canonical producer maxima. The public library's wider
caps admit those transport neighbors; this test does not claim the process's
6 MiB output guard or its post-sign UNKNOWN/no-ACK behavior ran. The same
qualification applies to the 2 MiB request and 1 MiB decoded PSBT transport
neighbors. Process guard integration needs separate acceptance evidence.
