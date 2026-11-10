# Attended offline mnemonic recovery

`mac-keyvault recovery generate|restore|pub|delete` manages an atomic pair from
one 24-word English BIP-39 flow, empty passphrase:

- Nostr `m/44'/1237'/0'/0/0`, no presence, x-only hex and npub.
- Namecoin account `m/84'/7'/0'`, `biometryAny` + `privateKeyUsage`, public
  mainnet xpub with `[fingerprint/84h/7h/0h]`. This account controls every
  receive/change child; it is broader than one leaf.

The scalar/account are separately wrapped by device-bound non-exportable
Secure Enclave P-256 keys. Only wrapped purpose material persists inside one
sole-vault-application Keychain item. No phrase/seed/root/common ancestor is
stored. Namecoin requires Touch ID, any enrolled finger and no password fallback.
No Namecoin spend/account-export operation is supplied by this interface.

Apply the main skill's OWNER-SITTING boundary to creation, restore, Keychain
inspection, deletion and signing. Prepare the exact physical/logical versions,
all retained public pins, expected prompts and complete write set first. The
human uses an unrecorded foreground terminal; an agent never captures its TTY.
The vault displays words only on `/dev/tty`, hides input, requires two offline
backups and confirms three distinct word positions before storage. Absence of
Touch ID for Nostr never supplies agent signing authority.

All three restore pins (npub, Namecoin xpub and origin) are mandatory and checked
before a wrapping key/item is created. A duplicate group or logical address
refuses without overwrite. A different valid mnemonic fails the public pins;
checksum alone does not detect every wrong word. Select every version explicitly.

Use a separately qualified matched hardened vault/helper pair. The source Go
builder `go run ./tools/recoverybuild --out ABSOLUTE_NEW_DIRECTORY` records hashes,
cdhashes and empty entitlements; it builds only and does not install or use keys.
Ad-hoc signing has no certificate/private signing key or TeamIdentifier. A new
binary changes identity and requires a deliberate attended adoption plan. Do not
replace an existing trusted executable or widen an ACL after refusal.

Ordinary Keychain access is vault-only; device wrapping does not establish
hardware caller-code enforcement for a blob separately obtained on this same
Mac. Nostr private material exists transiently in the paired vault processes.
Do not claim hardware secp256k1 non-extractability, universal buffer erasure,
recording protection or immunity to a compromised OS. Another Mac restores from
the off-Mac words and wraps under its own device keys.

Retirement is a separate exact action with KEEP default. A legacy item uses its
expected npub; a complete paired group uses its expected public group ID. A
Nostr projection cannot remove half a pair. Never print/export an old secret to
remove it. A failed/lost native response requires public-state reconciliation;
several removals are not one atomic transaction. Retired keys remain withdrawn
even when retained for backup.

Checkout-relative full contract and syntax: `docs/recovery.md`. Public reference
fixtures, isolated PTY/fake-store cases and signed public child controls are
source evidence; they do not qualify live Keychain, Secure Enclave or Touch ID.
