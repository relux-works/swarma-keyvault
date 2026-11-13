# Offline registration interoperability tests

This suite checks the identity registration CLI against keyvault's exported
public wire and PSBT interfaces. It imports no identity implementation package
and starts no signer, native helper, wallet or RPC client.

The existing eight Core fixtures remain unchanged. Their pinned request and
review-frame hashes, signatures and finalized transaction bytes are independent
reference outputs. A test adapter builds closed retained bundles from those
public records. Historical CLI checks must still succeed after actual request
and policy expiry; fresh requests against the same expired policy must refuse.

Fresh reserve/request tests use the actual clock and independently selected
public profile and account pin. Fresh reveal tests use a synthetic contemporary
retained reservation with the existing Core transactions and signatures. Only
public policy/request/receipt correlations change; no signature is produced.
They check both A/B parent results before reveal construction, then C/D requests,
exact review frames and completed public result verification.

Fresh CLI requests also pass the public process file preparation and create a
single-attempt runner context. Frozen historical requests restore through the
public reconcile descriptor without a synthetic historical signing clock.
A correct public ACK and Core result without native completion remains UNKNOWN
and releases no transaction; reducer observations are policy fixtures only.

Negative cases renew file commitments when testing semantic changes to original
IDs, expiry, frame, plan, pin and parent results. Result/ACK/signature/exit errors
must return their exact public error and no checked-result directory. Existing
output bytes must survive create-only refusal.

## Run

Use the Go version pinned by the root `go.mod`. Prepare public dependencies
separately, then execute tests offline with private PID/network/filesystem
namespaces and a disposable HOME, TMPDIR and Go caches. Mount only the public
sources, toolchain, prepared dependencies and independently built identity CLI;
keep host credentials and signing sockets outside the sandbox.

Build the identity CLI from its selected source revision with
`go build -o .temp/swarma-identity ./cmd/swarma-identity` in that repository.
Inside the prepared sandbox, run:

```sh
KEYVAULT_IDENTITY_CLI=/out/swarma-identity go test -p 1 -count=1 -v ./interop/namecoin-registration
go test -p 1 -count=1 ./internal/namecoinwire ./internal/namecoinpsbt ./internal/namecoinfiles
```

`KEYVAULT_IDENTITY_CLI` is an absolute path to the separately built public CLI.
Without it, the eight public fixture checks run, while CLI integration tests
explicitly skip. Such a run is not CLI docking evidence. Fixtures use private
temporary directories; retain command captures under the caller's `.temp/`.

These tests prove public interoperability for the exercised inputs. Synthetic
receipt/journal fields authenticate no protected history, owner presence,
preparation time or release permission. Native file-descriptor/process behavior,
Keychain, Touch ID, account derivation, initialization, timing and maximum-shape
result measurements need their separate qualification.
