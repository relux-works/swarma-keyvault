# CLI and record policy

## Choose a public or custody route

Source: `cmd/mac-keyvault/main.go` (`run`, `usageLines`, `runVerify`) and
`internal/keyvault/registry.go` (`registry`, `Operations`).

`mac-keyvault` uses direct verbs, not a `keys` group. The implemented key
primitive is P-256 ECDSA/SHA-256. Record `operations`/`findings` expose effective
capabilities; `via: reserved` is not executable support. General ECDH and private
export remain reserved. The Keychain ECIES decrypt route is the KEK broker.

Only the explicit public-file verification branch avoids constructing a vault
manager. Inert public-input example (not run):

```text
mac-keyvault --json verify --spki trusted-public.pem --data-file payload.bin --sig @payload.sig
```

It accepts existing P-256 DER/PEM public material and a binary DER signature.
Obtain the public pin independently. Verification proves a signature under that
key, not release/grant authority. `--raw` instead selects 64-byte `r||s`;
`--allow-high-s` explicitly relaxes the normal low-S policy and is not a default.

## OWNER-SITTING custody catalogue

These names and flags describe interfaces for the owner, never agent steps.
No key creation or Keychain-touching command is an agent action.

| Operation | Actual selector / boundary |
| --- | --- |
| `list` | Optional `--service S`, `--kind K`; may enumerate custody records |
| `describe S/P`, `pub S/P` | `--kind K`, `--version N`; `pub --format spki-der\|spki-pem\|jwk\|ssh`, optional `--out FILE` |
| `init` | New records only; `--service`, `--purpose`; `--enclave` and `--user-presence` are explicit policy choices, not repair switches |
| `sign S/P` | Exactly one of `--digest HEX\|@FILE`, `--data-file FILE`, `--stdin`; optional `--version`, `--kind`, `--format ecdsa-der-low-s\|ecdsa-raw`, `--raw`, `--out` |
| `verify S/P` | Vault-backed alternative to `--spki`; same input selectors plus `--sig HEX\|@FILE`; not a public-file-only operation |
| `rotate S/P` | Creates a new generation, retains the old one; separate authorization |
| `delete S/P` | Requires `--confirm`; select `--version N` explicitly for the intended generation |
| `meta get\|set\|unset S/P` | `--version`, `--kind`, and set's `--json-value`; metadata is not authorization |

Addresses are semantic `service/purpose`, normally kind `key`. Omitted/zero
`--version` selects newest; specify a positive generation for reviewed custody
work. Labels remain `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`;
raw labels are not addresses. Records use schema 2. Enclave and login-Keychain
stores are distinct; do not switch stores when policy or presence fails.

For signing, `--digest` is 64 hex characters or `@FILE` holding 32 raw bytes.
`--data-file`/`--stdin` hash input with SHA-256; feeding them a digest hashes it
again. Signature format defaults to the record policy, normally DER low-S;
select it explicitly where a protocol requires DER. Creation supports only the
implemented key primitive: reserved algorithm/kind names do not create working
providers. Extraction defaults to `none`; a record policy does not implement
private export or a `--human-authorized` command.

## Results and refusal

Ordinary commands accept `--json`; inspect process exit and `ok`, `error.code`,
`error.hint` together. Exit 0 is success, 2 usage, 3 policy refusal, 1 operational
failure. A well-formed but wrong signature produces `signature_invalid`, exit 1,
`verified:false`; malformed/high-S input can refuse before custody access.
`signer serve` has its own JSON-lines output, not this ordinary envelope.

Unreadable/invalid metadata, wrong usage, expiry and unsupported primitives do
not authorize fallback or record repair. Preserve the failure and selected
public identity. SPKI and OpenSSH fingerprints hash different representations;
compare the representation required by the consumer. Read
[recovery](validation-recovery.md) before proposing a mutation.
