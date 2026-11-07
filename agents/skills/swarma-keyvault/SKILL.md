---
name: swarma-keyvault
description: Work with Swarma Keyvault key custody, signer and SSH/KEK interfaces, and typed local, a2a or multi-use grants. Use for this repository's contracts and public verification; route signing and owner-presence operations to an OWNER-SITTING.
---

# Swarma Keyvault

Select the interface and trust profile before preparing input. This native
repository skill is the source for a future installed copy; it does not establish
installation, native qualification, live enrollment or deployment. Curator
profile publishing is outside this skill.

| Task | Read only the relevant reference |
| --- | --- |
| Key records, public verification, one-shot key operations | [CLI and record policy](references/cli.md) |
| Generation-bound JSON-lines signing session | [Signer contract 1](references/signer-1.md) |
| SSH authentication or Git SSH signing with new dedicated keys | [SSH interface](references/keyvault-ssh-new-keys.md) |
| Service KEK client integration | [KEK integration](references/kek-integration.md), then [broker boundaries](references/kek.md) |
| Repository certificate issue/request/execute and offline verify | [Typed local grants](references/grants.md) |
| Application-key grants and original-event verification/execution | [a2a grants](references/a2a.md) |
| Multi-use attestation, issue, publish, receive and root revocation | [Multi-use grants](references/multi-use.md) |
| Qualification, updates or refusal recovery | [Validation and recovery](references/validation-recovery.md) |

## Execution boundary

**OWNER-SITTING:** all signing and owner-presence flows require the selected
owner-led sitting. Explain the exact typed action, target, key generation,
independent public pin and expected digest/presence prompt before handing off.
The human alone handles OS confirmation. A denied, unavailable or mismatched
prompt ends that attempt: no loop, dialog automation, store fallback or ACL edit.
A non-presence requester/publisher key is still signing authority; its lack of
an OS prompt does not authorize an agent to invoke it.

An agent may inspect source and prepare public documents within the task's
permissions. Never make key creation, Keychain/Enclave inspection, signer startup,
SSH-agent startup, KEK unwrap/rebind or private signing an agent step. State
initialization and effect execution (`grants execute`, `a2a-state-init`,
`a2a-execute`, `mu-state-init`, `mu-execute`) need the custodian's
authorization for that exact state or request; they are not agent steps either. Even
`list`, `describe` and vault-backed `pub` can access Keychain. Public-file
`mac-keyvault verify --spki` and offline `swarma-keyvault grants verify` are
separate public verification routes; execute them only when the task permits
execution. Signing and effect examples are inert syntax. The public-only
verification example in [typed local grants](references/grants.md) has a confined runner; use
it only when the task permits execution.

Keep public verification, signing, enrollment, persistence, effect execution and
installation distinct. A public pin or successful signature does not supply
effect authority. Use separately trusted configuration and exact full identities;
request fields and display aliases do not enroll a key or owner. Preserve
UNKNOWN outcomes and their journals; failed output can follow an actual effect.

## Actual interfaces

`cmd/mac-keyvault` manages P-256 key records, `signer serve` and `ssh-agent`.
There is no `keys` or `kek` subcommand. KEK custody uses the separate
`cmd/mac-keyvault-kek` broker and public Go package
`github.com/relux-works/swarma-keyvault/pkg/kekclient`.
`cmd/swarma-keyvault` implements the typed `grants` command families above.
Their local, a2a and `swarm-envelope/2` formats are distinct; never interchange
them or use generic signing as an owner-grant issuance shortcut.

Custody requires the admitted macOS native backend and paired Enclave helper.
Portable verification and Linux library components do not imply portable custody
or a complete live Linux service. No public signer SDK, plugin registry or typed
release-signing command is provided. Checkout-relative source paths in references
identify implementation evidence, not files bundled into an installed skill.
