# Generation-bound signer: contract 1

For repeated operations on an already approved key, select the reviewed binary,
semantic address, kind and generation explicitly:

```sh
/absolute/reviewed/mac-keyvault signer serve --address new-service/signing --kind key --version 1
```

The server writes one JSON hello line, reads JSON request lines and writes one
response line per request in order. EOF ends the session. Startup refusal is an
`ok:false` hello and a nonzero CLI exit; inspect it before sending requests.
An ordinary declared request refusal does not end a running stream.

The successful hello has `contract:1`, `ok:true` and a `result` with `tool`,
`tool_version`, `address`, `kind`, `version`, `label`, `fingerprint` and `ops`.
Require the expected tool/address/kind, positive selected generation, all four
operations (`describe`, `pub`, `sign`, `verify`) and independently trusted key
fingerprint before any private request. If version was omitted, the newest
generation resolved at hello stays fixed until EOF; rotation never silently
changes a running session's key.

Minimal public requests after an accepted hello:

```json
{"id":1,"op":"describe"}
{"id":2,"op":"pub","format":"spki-der"}
```

`pub` also accepts `spki-pem`. For a separately authorized signature, `sign`
takes `digest` (64 hex characters) and `format` (`ecdsa-der-low-s` or `ecdsa-raw`).
`verify` takes those fields plus hexadecimal `signature` and `allow_high_s`.
Send only members admitted by that operation: even `allow_high_s:false` on
`sign` is `bad_request`, not an ignored default. IDs are non-null strings or
numbers. An invalid request can receive `id:null` with its declared refusal.

Success is `{id,ok:true,result}`. Refusal is
`{id,ok:false,error:{code,message,hint,os_status?}}`. A failed verification may
also carry `result.verified:false`. Accept only the closed error vocabulary,
shapes and field types in this source revision. Reject unknown, repeated
(including escaped-equivalent), missing or null members, trailing data and
operation/result mismatches before relying on decoded values. Do not resolve
duplicate members by retaining the last one.

Bind every answer to its pending ID, operation, inputs and accepted hello.
Require public-key fingerprint agreement, independently verify returned
signatures under that public key, and independently derive verification verdicts.
A validly shaped but mismatched signature is a protocol failure. A version or
protocol mismatch ends the client session; it is not a reason to downgrade or
continue using an unbound answer. Declared policy refusals remain distinct from
protocol failure.

The tested Go client in `internal/keyvault/signerclient` implements these checks,
but Go's `internal` boundary prevents external imports. There is no public signer
SDK or plugin registration interface in this initial module. Consumers must use
the actual wire contract or separately agree a public API. Its `Options` has no
configured-fingerprint field: an in-module consumer must compare
`Hello().Fingerprint` with its independently supplied pin before private use.
`CryptoSigner` supports SHA-256 digests and DER low-S output; its availability
does not turn a key into a certificate, grant or release authority.

Both supported stores retain their record policy on every operation. Owner
presence may be required for each signature. Neither a session nor a prior
signature waives expiry, usage or presence. See [CLI policy](cli.md) and
[recovery](validation-recovery.md).

In a source checkout, contract fixtures are
`internal/keyvault/testdata/signer-v1/*.json`, with production-driven golden and
strict-client tests. A changed wire contract needs a new contract version and
matching consumer acceptance; do not edit golden refusals to accommodate a
protocol violation.
