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
`NOSTR_IDENTITY/recovery@GROUP_VERSION`. A sole-application decrypt ACL trusts the
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

## Independent purpose identities

Nostr and Namecoin receive separate required public identity parameters. They
may be equal or different. The physical paired record is anchored by the Nostr
identity; its logical records are `A/nostr@N` and `B/namecoin@M`. Identities are
vault service names, not an OS account, Matrix account or inferred display name.

Before a mutation creates even a lock file, the vault displays the physical
record and both logical addresses and requires the user to retype A and B on
the controlling terminal. A mismatch or EOF leaves storage and lock prerequisites
untouched. Deletion requires the Namecoin identity as well as the physical
address and retained group pin, and confirms both identities too.

An advisory plan reads the actual public inventory without creating a lock or
its parent. It reuses an existing admitted lock when available. Each omitted
generation is the next number after the largest existing generation for that
specific identity and purpose, starting at 1; the three families advance
independently. Explicit generations are also allowed. The maximum is
2147483647; exhaustion refuses. The JSON result uses
`schema=keyvault-recovery-plan/1` and names both identities, all three generations
and all three addresses. It is a snapshot, not a reservation. Generate or
restore must receive the exact selected generations; a collision under the
mutation lock refuses without choosing a replacement or overwriting anything.

Example syntax for an attended operation:

```sh
mac-keyvault --json recovery plan --nostr-identity example --namecoin-identity wallet
mac-keyvault --json recovery generate --nostr-identity example --namecoin-identity wallet --version 1 --nostr-version 2 --namecoin-version 1
mac-keyvault --json recovery pub example --version 1
mac-keyvault nostr pub example/nostr --version 2 --format npub
mac-keyvault --json recovery restore --nostr-identity restored --namecoin-identity restored-wallet --version 1 --nostr-version 2 --namecoin-version 1 --expected-npub NPUB --expected-namecoin-xpub XPUB --expected-origin '[fingerprint/84h/7h/0h]'
```

The explicit legacy `--service S` alias selects A=B=S. It cannot be mixed
with either purpose identity flag. Missing identities, mixed forms, repeated
security parameters and malformed generations refuse before custody is
constructed. There is no identity default or environment override.

New paired records use `keyvault-recovery/2` with an explicit `service` in each
purpose; the top-level service must equal the Nostr service. New paired
ciphertext uses `keyvault-recovery-ciphertext/2` and the v2 metadata-binding
domain. The existing per-purpose envelope primitive is unchanged. V1 readers
retain their exact canonical bytes and binding domain, inheriting their one
service only for v1. V2 never falls back to the top-level service for a missing
purpose service. Each record schema accepts only its matching ciphertext
schema; reading an old record performs no migration or rewrapping.

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
mac-keyvault recovery delete qualification --namecoin-identity qualification-wallet --version 1 --expected-group-id PUBLIC_GROUP_ID
```

Choose KEEP by default when retaining an old backup. An explicit removal must
identify both purpose identities, one item and its retained public pin; an incorrect identity or pin or a definite
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

## Attended seed setup release

On the supported macOS architecture, verify the release archive and its
`SHA256SUMS`, then open an unrecorded foreground terminal in the extracted
directory. Use the current unprivileged macOS account and pass both identities:

```sh
./keyvault-seed --nostr-identity example-nostr --namecoin-identity example-wallet
```

An identity is 1–40 lowercase ASCII letters, digits or hyphens. The values
may be equal. Omit generations to get an advisory next generation for each
of the three record families, or use `--version`, `--nostr-version` and
`--namecoin-version` to request exact generations. The release assets are
normally beside the command; `--artifact-dir` selects an absolute directory.
If you set disposable names with `--qualification-nostr-identity` and
`--qualification-namecoin-identity`, supply both and use unused names.

The command checks its embedded manifest and code pins and reads the actual
public inventory. It shows both actual and disposable targets, the exact
installation files and vault lock path before asking you to retype the two
identities separately. It then installs a new private release directory under
`~/Library/Application Support/swarma-keyvault/bin/`; an existing destination
refuses. It creates no launchers and replaces no trusted binaries or ACLs.

The disposable restore uses a published public fixture in its own terminal.
The command checks its public signature, the read-only duplicate refusal and
the refused use by the release’s distinct qualification executable. Check the
sole-vault application ACL when asked. Keep the disposable record. The vault
then asks you to retype the actual identities and displays **one new 24-word
mnemonic** on the foreground terminal. Make two offline copies and confirm the
three hidden word prompts. Expect two Touch ID checks in total, one for each
pair. Decline a password prompt. The setup command never reads the real
mnemonic terminal or sends the words through its JSON output.

After public readback, stdout reports the exact selected identities, Nostr
x-only key and npub, and Namecoin account xpub and origin. Give a recipient
only the public fields they need. If a run stops after a mutation could have
occurred, keep the records and reconcile the indicated public addresses. An
`UNCONFIRMED` reference does not prove creation. Do not retry or delete based
on a lost or partial receipt.

Release builders use the existing matched-pair builder with `--seed-version`:

```sh
go run ./tools/recoverybuild --out /absolute/new/ignored/build-directory --seed-version v0.2.0
```

It builds the hardened vault/helper first, then the restricted qualification
binary and the manifest, then the seed utility with the exact manifest and
artifact pins. `SHA256SUMS` covers the shipped executables and manifest;
`build.log` is local build evidence, not a release asset. The manifest does
not include the utility’s hash; the outer checksum list does. The builder
does not install or exercise custody.

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
wrong-key/tag/pin/purpose cases, independent identity/version reservations,
first-user no-write planning, confirmed exact pair deletion, atomic-write/cleanup
refusal checks and isolated
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
