# Offline mnemonic recovery and device wrapping

`mac-keyvault recovery` derives two purposes from one 24-word English BIP-39
mnemonic, using an empty passphrase:

| Purpose | Fixed path | Retained authority | Hardware wrapping policy |
| --- | --- | --- | --- |
| Nostr | `m/44'/1237'/0'/0/0` | One BIP-340 leaf | No presence |
| Namecoin | `m/84'/7'/0'` | Account 0 scalar and chaincode, including every receive/change child | `privateKeyUsage` + `biometryAny` |

The Namecoin public account is an ordinary mainnet `xpub` with version
`0488B21E`, depth 3 and origin `[fingerprint/84h/7h/0h]`. It can feed receive
and change watch-only descriptors. This command does not implement address
registration, PSBT signing, transaction broadcasting or agent delegation.
The account controls more than one leaf. Its public xpub includes a public
chaincode; no private extended key is exported.

The vault obtains 256 bits from the OS random source. It displays the words
only on its foreground controlling `/dev/tty`, asks for two offline backups,
then hides the display and asks for three distinct random word positions.
Typing is hidden. Failed confirmation, EOF, cancellation, absent terminal or
invalid recovery input prevents storage. No seed, passphrase, private-key,
file, stdin, environment or clipboard argument route is provided. Keep the
selected human terminal outside recording and automated panes.

Generation/restore is an attended operation. Nostr wrapping has no OS presence
prompt. Namecoin wrapping is qualified by a silent authentication refusal and
then a successful Touch-ID-protected public ECDH fixture, before storage. Any
enrolled Touch ID finger can authorize; login-password fallback is excluded.
Unavailable, locked-out, denied or canceled authentication ends that attempt.
Adding fingerprints does not invalidate a `biometryAny` key. This differs from
`biometryCurrentSet` and from the password-permitting `userPresence` policy.

After confirmation, the vault persists one atomic paired recovery item in the
login Keychain under `works.relux.mac-keyvault.nostr.v1`, account
`SERVICE/recovery@GROUP_VERSION`. A sole-application decrypt ACL trusts the
current signed vault. Its public metadata links both purposes and public pins.
The value contains two separate ciphertext envelopes and their opaque device
wrapping-key representations. No mnemonic, entropy, BIP-39 seed, master key or
common ancestor persists. The Namecoin account and Nostr leaf have separate
Secure Enclave P-256 KeyAgreement wrapping keys with their respective policies.

The envelope algorithm is
`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`: ephemeral
uncompressed P-256 point, ECDH, X9.63 SHA-256 with that point as shared info,
16-byte AES key and 16-byte derived GCM IV, followed by ciphertext and tag.
Plaintext includes a role-specific length and binding to the complete public
record, physical account, logical purpose/version and wrapping point. Duplicate
or unknown JSON fields, noncanonical encodings, unexpected algorithms/policies,
wrong points, swapped purposes and invalid sizes refuse. There is no software
wrapping fallback. Public read/export does not unseal either purpose.

The Nostr projection retains `nostr-key/1` public fields and explicitly reports
`storage=enclave-wrapped-keychain`, `presence=false`, `private_export=false`.
Legacy random-key records remain explicitly `storage=keychain-acl`; they are
not silently interpreted as wrapped recovery records. A duplicate physical or
logical address in either creation order refuses. Recovery checks before words
are requested and again before atomic add; legacy generation checks the physical
recovery account and both logical purposes under the same vault lock.
Nothing is overwritten, rotated or removed during generation or restore.

Example syntax for the selected human sitting:

```sh
mac-keyvault --json recovery generate --service example --version 1 --nostr-version 2 --namecoin-version 1
mac-keyvault --json recovery pub example --version 1
mac-keyvault nostr pub example/nostr --version 2 --format npub
mac-keyvault --json recovery restore --service restored --version 1 --nostr-version 2 --namecoin-version 1 --expected-npub NPUB --expected-namecoin-xpub XPUB --expected-origin '[fingerprint/84h/7h/0h]'
```

Restore reads exactly 24 words once, with echo disabled, and compares all three
retained public pins **before creating a wrapping key or storing an item**.
This catches a different valid mnemonic as well as checksum errors. A BIP-39
checksum alone misses some word errors. Another Mac restores the same public
identities from the words and creates its own device wraps. The off-Mac words
are therefore the portable backup. Twelve-word NIP-06 examples are low-level
test vectors; the product restore interface admits only 24 words.

Removal is a separate, exact operation:

```sh
mac-keyvault nostr delete example/nostr --version 1 --expected-npub OLD_NPUB
mac-keyvault recovery delete qualification --version 1 --expected-group-id PUBLIC_GROUP_ID
```

Choose KEEP by default when retaining an old backup. An explicit removal must
identify one item and its retained public pin; an incorrect pin or a definite
pre-effect refusal preserves it. Deleting half a pair is not supported. The vault never reads the old
private value to remove it. A lost/nonzero response can follow a native effect;
the process returns exit 1 and `recovery_outcome_unknown` when the native
mutation cannot be confirmed. In JSON, `ok=false` and that error accompany
`result={outcome:"unknown",operation:"generate"|"restore"|"delete",reference:PUBLIC_RECORD}`.
The reference is explicitly UNCONFIRMED, not proof of creation or deletion.
Definite pre-effect and duplicate refusals remain distinct. The native bridge
marks the actual mutation-call boundary, so a code-policy refusal before any
Keychain query cannot be mistaken for an uncertain write. Failed or short
receipt writes also return exit 1 and attempt one bounded public diagnostic.
Mutation output handles SIGPIPE so a closed stdout pipe returns EPIPE and
reaches that diagnostic when stderr remains available.
If either output channel is lost, retain UNKNOWN. Reconcile the public reference;
do not automatically retry or delete. Several removals are separate
effects, not a transaction. Retained retired keys are not an active identity.

## Binary and memory boundary

Build a matched pair from a clean committed checkout using:

```sh
go run ./tools/recoverybuild --out /absolute/new/ignored/build-directory
```

The Go tool builds/signs the helper first, embeds its exact cdhash into the
vault, and signs both ad hoc with hardened runtime. Its manifest records the
source head/tree, tool versions, SHA-256, cdhash, flags and empty entitlements;
`build.log` retains build diagnostics in that new directory. The tool refuses
an existing output directory and performs no installation or custody operation.
There is no code-signing certificate/private key or TeamIdentifier in this
ad-hoc route. A changed executable is a new code identity; later adoption needs
an attended plan preserving the sole-application ACL. Never replace old trusted
binaries, expand the application list or retry a denial under weaker policy.

Before sending any private-helper request, the vault validates its own runtime
policy and the actual blocked child process against the compiled helper pin.
No helper path/environment override is provided. The helper requires pipe input
and output; bounded framed responses carry private Nostr plaintext only inside
the paired vault process boundary. No Namecoin account-returning operation is
provided. Private data never reaches the public CLI stdout/stderr.

The P-256 wrapping keys are non-exportable hardware keys. The Nostr scalar and
Namecoin account are recoverable software material, transiently present during
derivation/use. Explicit owned buffers are cleared; runtime/library copies, OS
memory, terminal history/recordings and abrupt process/host loss cannot all be
erased or excluded. Screen clearing is best effort, not a history guarantee.
Hardened runtime and SIP protect supported task-port/injection boundaries; they
do not make a compromised OS safe or keep secp256k1 out of Mac memory.

Device wrapping makes copied ciphertext/blob unusable off this Mac. Normal
Keychain access is vault-only, but this design does not claim hardware caller-
code enforcement after a same-user attacker separately obtains the blob/value
and login access on this Mac. The Nostr wrap has no presence requirement;
Namecoin additionally requires Touch ID. Device binding is not application
binding. Hardware caller-code attestation and an external secp256k1 signer are
outside this interface.

## Verification

`go test -race ./internal/keyvault ./cmd/mac-keyvault ./tools/recoverybuild`
includes published NIP-06/BIP-32 cases, an unmodified reference fixture set,
wrong-key/tag/pin/purpose cases, atomic-write/cleanup refusal checks and isolated
PTY controls with a fake custody implementation. Public-output leak plants
exercise the checker with each synthetic fixture word. Actual running signed
public helper fixtures test the code-admission boundary without Keychain use.
On macOS, an isolated test-only Go/cgo binding to Apple's in-memory SecKey
primitive checks both production ECIES lengths and wrong-key/tag refusals;
it never queries Keychain or creates an Enclave key. Independent public-account
receive/change fixtures also match private-account child derivation.
Fake/software tests do not qualify live Secure Enclave, Keychain ACLs or Touch
ID. Attended native qualification separately checks those properties with a
disposable paired group and the selected actual group.

Reference regeneration and pins are documented in
[`tools/recoveryreference`](../tools/recoveryreference/README.md) and
[`testdata/recovery`](../internal/keyvault/testdata/recovery/README.md).
