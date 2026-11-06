# Generation-bound signer: contract 1

## OWNER-SITTING session

Source: `cmd/mac-keyvault/main.go` (`runSigner`),
`internal/keyvault/signer.go` (`SignerServer`, `allowedMembers`) and
`internal/keyvault/signerclient/`. Starting a session accesses custody and is
not an agent inspection step. Inert owner syntax:

```text
mac-keyvault signer serve --address selected-service/signing --kind key --version 1
```

The server emits one JSON hello, then answers nonblank JSON request lines until
EOF. A startup refusal is `contract:1, ok:false` and a nonzero CLI exit. A request
refusal normally leaves the stream running. The accepted hello's result names
`tool`, `tool_version`, `address`, `kind`, `version`, `label`, `fingerprint`, `ops`.
Require the intended tool/address/kind, positive generation and independently
trusted fingerprint before private use. If version was omitted, the generation
resolved at hello stays pinned through EOF; rotation does not switch it.

## Operation-specific wire input

Public requests after the owner has admitted the session:

```json
{"id":1,"op":"describe"}
{"id":2,"op":"pub","format":"spki-der"}
```

`pub` also accepts `spki-pem`. OWNER-SITTING `sign` accepts `digest` (64 hex)
and `format` (`ecdsa-der-low-s` or `ecdsa-raw`). `verify` adds hexadecimal
`signature` and optional `allow_high_s`. IDs are non-null strings or numbers.
Unknown members are refused by presence: `allow_high_s:false` on `sign` is
`bad_request`, not an ignored default. Duplicate names, including escaped
aliases and nested duplicates, are refused. Invalid requests can use `id:null`.

Success is `{id,ok:true,result}`; refusal is
`{id,ok:false,error:{code,message,hint,os_status?}}`, with a verification result
where applicable. Use the exact source version's closed shapes and errors.
Bind each response to the pending ID, operation, inputs and accepted hello.
Check returned public fingerprint and independently verify signatures/verdicts;
a well-shaped mismatched answer is a protocol failure, not a successful sign.
Stop on a contract/version mismatch instead of downgrading.

## Client and policy boundaries

The checked client is internal to this Go module; external consumers cannot
import `internal/keyvault/signerclient`. Its `Options` does not accept a trusted
fingerprint option: an in-module caller must compare `Hello().Fingerprint` to
its separate pin before private use. `CryptoSigner` supports SHA-256 and DER
low-S; this supplies no grant or release authority. There is no public signer
SDK or plugin registration API here.

Record validity, usages and store policy are rechecked per operation. A session
or prior signature does not waive owner presence. Stop after refusal; do not
retry prompts or recreate keys. Fixtures under
`internal/keyvault/testdata/signer-v1/` and strict-client tests are source test
evidence, not native or installed qualification. See [recovery](validation-recovery.md).
