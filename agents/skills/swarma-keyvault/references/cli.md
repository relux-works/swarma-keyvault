# CLI and record policy

Use the reviewed `mac-keyvault` binary that is qualified for the selected key.
The following commands are examples to adapt after resolving their actual
address, files and authorization, not a batch to execute automatically.

## Public-only first use

Inspect an existing record and its explicit generation:

```sh
/absolute/reviewed/mac-keyvault --json list --service new-service
/absolute/reviewed/mac-keyvault --json describe new-service/auth --version 1
/absolute/reviewed/mac-keyvault pub new-service/auth --version 1 --format spki-pem
```

Select `operations` by name/input/output. The implemented primitive is P-256
ECDSA/SHA-256; `via: reserved` entries, including general ECDH, are unavailable.
SPKI fingerprints and OpenSSH fingerprints hash different public representations.
Pin the representation the consumer actually verifies, using independently
trusted public material rather than accepting whatever the current tool returns.

Foreign signature verification can avoid vault lookup entirely:

```sh
/absolute/reviewed/mac-keyvault --json verify --spki trusted-public.pem --data-file payload.bin --sig @payload.sig
```

This example expects an existing P-256 DER/PEM public key, payload and binary DER
signature. A successful verification proves the supplied key signed the supplied
digest; it does not establish that the key has release or grant authority.

## Records and explicit mutations

Addresses are `service/purpose`, with `--kind key` by default and `--version N`
selecting a generation. Omission selects the newest generation for a one-shot
command. Labels are derived as
`works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`; never pass a raw label
as an address. Records use schema 2. Preserve labels, generations and storage
locations across a module update.

Only after authorization for a new address, an example login-Keychain key is:

```sh
/absolute/reviewed/mac-keyvault --json init --service new-service --purpose signing --title 'New service signing' --usages sign,verify
```

Stop if the address already exists. Keep authentication, service KEK and
owner-authority purposes separate. `--enclave --user-presence` selects a distinct
device-bound owner-presence key; it is not appropriate for unattended signing.
`--user-presence` on the ordinary Keychain store can fail with
`missing_entitlement`/OSStatus -34018; do not switch stores to make it succeed.
The helper must remain paired with its CLI. Missing helper support refuses use.

Authorized one-shot signing accepts exactly one input source:

```sh
/absolute/reviewed/mac-keyvault --json sign new-service/signing --version 1 --data-file payload.bin --out payload.sig
```

`--digest` accepts 64 hexadecimal characters or `@FILE` containing 32 raw digest
bytes. `--data-file` and `--stdin` hash their input with SHA-256. The default
signature is strict DER low-S; `--raw` emits 64-byte `r||s`. Match the format when
verifying. Do not enable `--allow-high-s` by default.

`rotate service/purpose` creates a new generation and retains the old key.
`delete service/purpose --confirm --version N` deletes the explicitly selected
generation. `meta get|set|unset` reads or changes metadata; metadata is not an
authorization channel. These are distinct mutations, not automatic fixes for a
failed signature or invalid record. Preserve data and obtain the actual recovery
decision before deleting/recreating an unusable record.

Extraction defaults to `none`. Never select `--extraction agent` without the
explicit human choice. `export-private` and `--human-authorized` are not implemented.

## Refusals

Use `--json`, the process exit status, and `error.code`/`error.hint` together.
JSON outcomes go to stdout; ordinary command errors do not require parsing text
stderr. Exit 0 is success, 2 usage, 3 policy refusal, and 1 operational failure.
Verification has a meaningful negative result: `signature_invalid` is exit 1
with `verified:false`; malformed or high-S signatures are policy refusals.

Invalid inputs, wrong usages, expiry, unreadable or invalid metadata, and
unsupported primitives must not lead to a private operation or partial rewrite.
`record_unreadable`, `record_invalid:<code>` and `unsupported_primitive` findings
require diagnosis before use. Unknown metadata is not permission to assume the
Keychain store. Preserve the exact failure class; do not retry a denied or
headless Keychain/presence prompt or repair it by changing permissions.
