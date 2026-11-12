# Public native-selection fixtures

These four exact canonical JSON profiles select the existing public Core/BIP32
transaction fixtures independently of their request bytes. They use an explicit
historical fixture clock and the disposable regtest configuration already pinned
by those fixtures. They are not production policy or current requests.

Every sidecar GroupID, NostrPublicPin, MetadataHash and PairedValueHash is zero:
these are intentional syntax-only placeholders. No live retained pair, private
Keychain value, native protected anchor, owner approval, release or custody
provenance is represented. A production adapter must populate and independently
verify its actual retained setup and selected item before any private operation.

Reservation profiles encode nil RevealValuesPin as JSON null, the canonical Go
representation. Reveal profiles carry the exact separate public values-pin file
as standard padded base64. The CLI integration must retain its separate selected
values-pin gate; a transaction request cannot supply that authority.

SHA256.json lists exact complete file sizes and hashes. Tests cover the literal
canonical representations and explicit fixture clock admission, paired with
malformed/changed/mismatched expected hashes. A matching hash alone does not
establish that the expected hash came from an admitted source.
