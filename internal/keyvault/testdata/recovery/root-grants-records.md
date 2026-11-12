# Root grants public metadata and sealed representation fixtures

The root sidecar source uses schema `keyvault-root-grants/1`, physical Keychain
service `works.relux.mac-keyvault.root-grants.v1`, and the exact explicit account
`<grants-identity>/root-grants@<version>`. Versions are1..2147483647; identities
use the existing1..40 lowercase ASCII letters/digits/hyphens grammar. There is
no implicit identity, latest generation, overwrite, adoption or pair migration.

Public metadata order is exactly `schema`, `service`, `purpose`, `version`,
`created`, `profile`, `derivation`, `path`, `algorithm`, `presence`, `public_key`,
`seal_public_key`, `seal_script`, `pair`, `wrapping_point`, `wrapping_fingerprint`.
The nested pair uses exactly `schema`, `service`, `version`, `group_id`,
`metadata_sha256`, `nostr_identity`, `nostr_version`, `nostr_public_key`,
`nostr_npub`, `namecoin_identity`, `namecoin_version`, `namecoin_xpub`,
`namecoin_origin`. Its digest covers the complete exact canonical retained public
record, including creation time and wrapping metadata, not a projection.

The profile remains `namecoin-landlord-root/1`, derivation `bip85-hdseed-wif/1`,
fixed path `m/83696968h/2h/7h`; Nostr/Namecoin paths and policies remain unchanged.
The metadata algorithm is `secp256k1-bip340+ecdsa` and presence policy is
`biometry-any-per-signature`. Those fields describe the required policy; a
public constructor does not establish enrollment, key possession or enforcement.

K must be a valid lowercase64-hex BIP340 x-only point. The seal public point is
exactly `02||K`, and its script is `76a914||HASH160(02||K)||88ac`. An x coordinate
is checked against the curve field/point rule, not the private scalar order.
Private exponent range1≤d<n, even Y and correspondence with K are checked only
inside the private package. Dates are canonical UTC RFC3339 seconds. Metadata
is at most32768 bytes. Unknown/duplicate/escaped or case-aliased fields, NULL,
reordering, trailing bytes and noncanonical JSON/base64/hex encodings refuse.

The separately sealed representation has schema
`keyvault-root-grants-ciphertext/1`, ordered `schema`, `algorithm`,
`enclave_blob`, `point`, `fingerprint`, `ciphertext`. Its ECIES algorithm is the
existing `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
from [the recovery contract](../../../../docs/recovery.md):65-byte uncompressed
P256 ephemeral point, X9.63 SHA256 with that point as shared info,16-byte AES key
and16-byte GCM IV,68-byte encrypted plaintext and16-byte tag. Ciphertext is
exactly149 bytes; the opaque device blob is1..16384 bytes, total envelope at
most65536 bytes. All byte strings use standard padded canonical base64. The
wrapping point is a valid65-byte P256 point matching the metadata and its SHA256
fingerprint. A point/shape/hash check never authenticates a seal or device blob.

The private binding is `KVG1 || SHA256("keyvault-root-grants/plaintext/1" || 00 ||
complete-canonical-metadata) || normalized-scalar32`, exactly68 bytes. Private
objects have no exported constructor/getter or plaintext/scalar callback, use
fixed formatting and refuse JSON serialization. Their engine owner must clear
both the original prepared material and the binding buffer on success, failure
and cancellation. Copies of a binding share its cleared allocation. This is
logical lifetime control, not guaranteed erasure of compiler/runtime copies.

## Fixture authorities and proof limits

The public scalar3/K anchor and original pair fixture provenance are preserved
in [root-grants-vectors.md](root-grants-vectors.md) and [README.md](README.md).
Record tests independently construct the seal script using SHA256/RIPEMD160.
The wrapping-point fixture uses deliberately public synthetic P256 scalar3;
it is never a real device key or a newly qualified wrapping key. v1 service
inheritance, v2 split/equal identities, independent purpose versions and upper
version boundaries are all legitimate inputs paired with negative mutations.

Envelope tests intentionally reuse `v1-public-ciphertext.json`'s Nostr ciphertext
under DIFFERENT root metadata/wrapping point. Its149-byte form and real P256
ephemeral prefix are structurally valid; it is NOT a correct root seal. Passing
the parser therefore proves only the representation predicate. No decryption or
encryption is attempted by those tests. Native helper key/binding verification,
fresh wrapping qualification, code admission and sole-vault ACL remain separate.

The private finite attachment source accepts only an opaque prepared handle plus
strict public metadata/sealed representation. It consumes the prepared scalar.
Its public-only vault interface takes an EXISTING mutation guard, reads only
the exact retained pair's public metadata, checks a root-address collision,
rechecks full metadata/pins, and dispatches one atomic create-only root add.
Public readback and a final unchanged-pair check precede a stored receipt. The
same guard spans all checks. The public preflight retains it BEFORE the future
attended helper's word entry/derivation/sealing phase; commit transfers that
same guard without a release/relock gap. Cancellation through copied leases
releases it once. A missing guard cannot use FileLock's directory
bootstrap fallback or create prerequisites. No old private read/decrypt/update/
delete/adopt/migrate operation, general store or plaintext sink is exposed.

The real adapter must enforce actual qualified helper sealing and sole signed
vault ACL; fakes do not certify either. Copies of an attempt share one state.
Pre-add failure is not_applied. A generic/possibly-applied add error, canceled
post-add attempt, malformed/lost readback or post-add pair change is UNKNOWN.
Only closed root-specific backend guarantees establish definite non-application;
legacy guarantees or unknown reasons do not. UNKNOWN survives replay aliases;
no retry, new generation, rollback or delete operation exists. Private native
admission/ABI and the same recovery utility's attended input remain unwired.

Public export rechecks the retained pair and emits only profile/path/address,
K/even seal point/script and public pair binding. The exact compact registration
value is `{"nostr":{"names":{"_":"S"}},"swarma":{"landlord":{"grant":"K"}}}`
with real validated lowercase x-only pins replacing S/K, no newline, plus a
separate byte length and SHA256. It contains no device representation, ciphertext,
npub in `grant`, private capability, enrollment or publication action. Fresh
all3 creation/restore and live typed grant/contract/seal signing stay unavailable.
