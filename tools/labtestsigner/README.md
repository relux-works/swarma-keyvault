# Local certificate and request test signer

This separate lab executable creates throwaway P-256 test keys and signs the
existing prepared local grant payloads. It is not part of the release KeyVault
CLI and provides no hardware fallback. Use only generated test keys in an
offline private sandbox. Its output establishes software signature behavior,
not protected key custody, Matrix identity, or authority from a real owner.

Build with the repository's exact pinned toolchain and dependencies:

```sh
go build -o /private/build/labtestsigner ./tools/labtestsigner
go build -o /private/build/swarma-keyvault ./cmd/swarma-keyvault
```

All paths below are absolute private sandbox paths. The parent of each private
key must be mode 0700 and each PKCS8 DER key must be a regular mode 0600 file.
`keygen` requires a new directory and generates owner, requester and adversarial
test keys; it prints no key material. Public `.der` files may be exported.

```sh
labtestsigner keygen --dir /private/custody/actors
swarma-keyvault grants local-prepare \
  --plan /private/tmp/plan.json --owner-mxid '@alexis:gr.relux.works' \
  --issuer-spki-der /private/custody/actors/owner.der \
  --requester-spki-der /private/custody/actors/requester.der \
  > /private/tmp/prepared.json 2> /private/tmp/review.txt
labtestsigner certificate --payload /private/tmp/prepared.json \
  --digest EXACT_LOWERCASE_HEX_DIGEST_FROM_REVIEW \
  --key /private/custody/actors/owner.pk8 \
  --owner-spki /private/custody/actors/owner.der \
  --requester-spki /private/custody/actors/requester.der \
  > /private/tmp/certificate.json
labtestsigner prepare-request --payload /private/tmp/operation.json \
  --requester-spki /private/custody/actors/requester.der
labtestsigner request --payload /private/tmp/operation.json \
  --digest EXACT_LOWERCASE_HEX_DIGEST_FROM_PREPARE_REQUEST \
  --key /private/custody/actors/requester.pk8 \
  --requester-spki /private/custody/actors/requester.der \
  > /private/tmp/request.json
```

`local-prepare` stdout is consumed byte for byte, including the existing closed
schema and no trailing LF. Its separate review supplies the exact digest.
`prepare-request` uses the existing public request preparation API, emits a
64-character digest, and never loads a private key. Both signing modes recompute
that digest through existing KeyVault APIs and reject any mismatch before
loading the key. They require the local key's SPKI to match its independent pin.

Certificate mode also accepts `--owner-mxid EXPECTED_OWNER`. Supply this from
independently installed test policy, never from the payload, key, requester or
name record. Omission preserves `@alexis:gr.relux.works`. For a synthetic
Ivan-to-Alexis-agent certificate, prepare the payload with the existing
`local-prepare --owner-mxid '@ivan:example.invalid'`, then pass
`--owner-mxid '@ivan:example.invalid'` to `labtestsigner certificate` as well.
That same payload refuses with the omitted default or a different expected
owner. Empty, missing and duplicate owner options refuse; the option is invalid
in `keygen`, `prepare-request` and `request` modes. Owner syntax and exact owner
binding are checked by the existing issuance API before any private key read.

Certificate signatures cover `swarma-grants/local-certificate/1`, LF, and exact
payload bytes. Requests cover `swarma-grants/local-request/2`, LF, and exact
payload bytes. They use SHA-256 and strict low-S P-256 DER. Certificate owner
must match the independent expectation; purpose remains `grants-owner-v1`.
The certificate binds SHA-256 of requester DER. Envelopes remain
`grants-signed-local-certificate-1` and `grants-local-request-2`. No wire type is
added. The serialized certificate must be under 98304 bytes and request under
12288 bytes.

The thin slice names are `id/swarma-poc-alexis` and
`id/swarma-poc-ivan-agent`. These labels do not perform a Namecoin lookup.
Enrollment uses the existing `grants-local-enrollment-2` schema with unpadded
base64url SPKI strings. The CLI verifies `repository.create` on the fixed
`relux-works/matrix-grants-poc-261031` target. It performs no repository action.
The signer component controls cover both synthetic owner directions. Reverse
verifier, wrapper and assembly qualification require their separate exact
source graphs and independent reviews; this option does not qualify them.

Integration checks drive the unchanged CLI with a public-only enrollment, an
explicit observation instant and absent state/provider paths:

```sh
KEYVAULT_BIN=/private/build/swarma-keyvault \
  go test -count=1 -v ./tools/labtestsigner
```

Optional `-lab-public-output=ABSOLUTE_DIRECTORY` exports public fixtures and
`-lab-private-custody=ABSOLUTE_NEW_DIRECTORY` retains that test's own throwaway
keys locally for a later authorized integration actor. Never include that
custody directory in an export. Without these flags, keys use the test's
temporary directory. Whole-prototype independent review and its exact marker
remain required before any mainnet use.
