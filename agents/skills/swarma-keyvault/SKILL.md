---
name: swarma-keyvault
description: Use mac-keyvault for macOS non-extractable P-256 keys, signer contract 1, the SSH agent bridge, and service KEKs through kek-1. Covers interface selection, public verification, onboarding, conformance, and recovery. Does not implement certificate grants or typed release signing.
---

# swarma-keyvault

Select the interface by operation, key purpose, store and contract. This package
documents the standalone compatibility component; its availability does not
establish which binary or consumer release is installed or authorize a live
custody change.

| Need | Interface / reference |
| --- | --- |
| Inspect a record, export its public half, sign once or verify | [CLI and record policy](references/cli.md) |
| Keep a generation-bound signing session | [Signer contract 1](references/signer-1.md) |
| Protect a service's 32-byte KEK | [KEK integration](references/kek-integration.md), then [complete kek-1 contract](references/kek.md) |
| Onboard new SSH authentication or Git SSH signing keys | [SSH/new-key guide](references/keyvault-ssh-new-keys.md) |
| Build, validate, update, or diagnose unavailable custody | [Validation and recovery](references/validation-recovery.md) |

## Establish the actual target

Use an explicitly selected reviewed binary and source revision. Initial custody
support is macOS with cgo/Security.framework and, for Enclave records, the paired
Swift/CryptoKit helper. A portable parser or client is not another platform's
custody backend. Local build artifacts are separate from installed binaries.

Record the semantic address `service/purpose`, kind (normally `key`), explicit
generation, independently trusted public fingerprint, store, usages and intended
operation. `describe`/`list` expose `operations` and `findings`: `via: reserved`
does not implement an operation. General ECDH, private-key export, imported SSH
keys, certificate/grant issuance and a typed release-signing service are not
provided by this compatibility interface. Generic `sign` and a Git-namespace SSH
socket cannot substitute for those services.

For an existing approved key, a minimal read-only inspection is:

```sh
/absolute/reviewed/mac-keyvault --json describe new-service/auth --version 1
```

`new-service/auth` is a placeholder, not a request to create a key. For verification
without vault access, use `verify --spki` with an independently obtained P-256
public key; the CLI reference gives the complete example.

## Preserve custody boundaries

Read/public inspection, new-key creation, private use, rotation/deletion, service
rebind and installation are different operations. Apply the user's existing
authorization to the exact operation; documentation examples do not grant it.
Never log private keys, KEKs, decrypted data, prompt credentials or signing input.
Use controlled error classes instead of forwarding raw broker stderr or paths.

Keep owner-presence keys separate from unattended service keys. For an authorized
presence signature, state the expected action/digest prompt before invoking it;
the human answers the OS prompt. A denied or unavailable prompt ends that attempt.
Do not retry it in a loop, automate the dialog, change ACLs or fall back between
Keychain and Enclave. A confirmation hook is consent UX, not hardware presence.

Use only new keys for SSH onboarding. Preserve existing SSH keys, registrations,
host selection, signing settings and historical verification trust. Same-user
socket access and code binding do not attest an individual agent or an approved
release. Follow the reference's forwarding, namespace and audit limits.

Unreadable metadata, missing keys, invalid envelopes or failed authenticated-store
checks stop the operation. Do not recover by generating a replacement KEK,
starting an empty store, deleting a key or weakening its policy. Preserve evidence
and use the recovery reference.

## Consumers and extensions

The supported external Go import is
`github.com/relux-works/swarma-keyvault/pkg/kekclient`. Select an exact reviewed
release/revision through the consumer's normal dependency configuration; a skill
install does not repin an existing consumer. Import paths from the old module have
distinct Go type and sentinel identities.

`internal/keyvault/signerclient` remains internal to this module. External users
must not import it or assume a supported public signer SDK. Contract 1 remains the
documented CLI wire interface. There is no public plugin registration API,
plugin directory or provider-selector framework in this extraction; integrate
through the real CLI/client interfaces rather than inventing a plugin seam.

Run only the validation appropriate to the selected contract and admitted
environment. Fake-backed confinement, read-only native qualification, attended
private tests and actual installed consumer acceptance prove different things.
Report skipped or unavailable lanes explicitly. Installation and profile adoption
require their supported package route and fresh installed readback; source files
and a successful build alone do not prove adoption.
