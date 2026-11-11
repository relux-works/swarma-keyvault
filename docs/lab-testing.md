# Offline lab fixture prerequisites

The full `go test -race ./...` suite includes subprocess controls in
`lab/namecoinwrapper` and `tools/labownnode`. They require six separately built
executables. Missing fixtures cause **NOT RUN** diagnostics and a nonzero suite
exit; those lanes have not passed. Do not use `-skip`, package exclusions or
`t.Skip` to turn a missing fixture into a green full-suite result. Hosted CI
continues to require these fixtures and runs every Linux-buildable package.

| Variable | Required executable and source |
| --- | --- |
| `LAB_KEYVAULT_CLI` | Independent configurable verifier, commit `12b3ffac1993cc5b35074b569018b4db7c9bbd82`, tree `a553906c37721d8f2adbdb1051cf1cef0eb54c49` |
| `LAB_CANDIDATE_KEYVAULT_CLI` | `cmd/swarma-keyvault` built from the candidate for the wrapper docking check |
| `LAB_TEST_SIGNER` | Explicit-owner synthetic lab signer, commit `1045aac3ea204722aaaf0e60dac69eb8f622a7fb`, tree `b129a24428cdf5f2cc56fa5d9f27749c4a12065a` |
| `LAB_COMPOSE` | `tools/labcompose` built from the candidate |
| `LAB_OWN_NODE` | `tools/labownnode` built from the candidate |
| `LAB_NODE_FIXTURE_CLI` | Non-race `go test -c` binary for candidate `lab/namecoinwrapper` |

`KEYVAULT_BIN` aliases the independent verifier for existing CLI controls.
The pinned verifier and candidate verifier exercise independent source builds.
These are inert offline controls with synthetic custody and public node replies;
they do not qualify native custody, a live node or an installed route.

Use the toolchain pinned by `go.mod`, Git, a POSIX shell and `shasum` (or use
`sha256sum -c` for the equivalent checksum check on Linux). On macOS install
Apple Command Line Tools for cgo and retain the real `HOME`. Put `TMPDIR`,
`GOCACHE`, `GOMODCACHE` and `GOPATH` in private test scratch before running the
commands. Keep the `TMPDIR` spelling short enough for Unix socket controls
(the socket pathname must be shorter than 104 bytes); a short alias to private
scratch can be used when the workspace path is deeply nested. All fixture paths must be absolute; binaries must be executable,
owned by the test UID, regular files and not symlinks. Keep the private parent
and binaries immutable during tests. No installation or signing is needed.

From the candidate repository root, run this in one shell. It builds the same
source commits, trees, bundle checksum and five executables as
[hosted CI](../.github/workflows/hosted-ci.yml). A separate source directory
keeps the immutable verifier and signer outside the candidate module.

```sh
set -eu
export MAC_KEYVAULT_SKIP_KEYCHAIN=1
# Match hosted CI's bounded build/test concurrency.
export GOMAXPROCS=2
export GOFLAGS='-mod=readonly -p=2'
candidate_source=$(pwd -P)
lab_root=$(mktemp -d "${TMPDIR:-/tmp}/keyvault-lab.XXXXXXXX")
chmod 700 "$lab_root"
fixture_source="$lab_root/source"
fixture_bin="$lab_root/bin"
mkdir -m 700 "$fixture_bin"
printf '%s\n' 'd0e442e35940972cf5fa7298df922e32c1cdf5b6024c5268115506a204abcd89  .github/fixtures/pinned-lab.bundle' | shasum -a 256 -c -
git clone --no-hardlinks --no-checkout "$candidate_source" "$fixture_source"
git -C "$fixture_source" checkout --detach dffe3ac5c86e2e8869efc3b869d35f845e1bd71a
test "$(git -C "$fixture_source" rev-parse HEAD)" = dffe3ac5c86e2e8869efc3b869d35f845e1bd71a
git -C "$fixture_source" fetch "$candidate_source/.github/fixtures/pinned-lab.bundle" refs/fixtures/verifier refs/fixtures/signer
git -C "$fixture_source" checkout --detach 12b3ffac1993cc5b35074b569018b4db7c9bbd82
test "$(git -C "$fixture_source" rev-parse HEAD^{tree})" = a553906c37721d8f2adbdb1051cf1cef0eb54c49
(
  cd "$fixture_source"
  go mod download
  go mod verify
  go build -o "$fixture_bin/swarma-keyvault" ./cmd/swarma-keyvault
)
git -C "$fixture_source" checkout --detach 1045aac3ea204722aaaf0e60dac69eb8f622a7fb
test "$(git -C "$fixture_source" rev-parse HEAD^{tree})" = b129a24428cdf5f2cc56fa5d9f27749c4a12065a
(
  cd "$fixture_source"
  go mod download
  go mod verify
  go build -o "$fixture_bin/labtestsigner" ./tools/labtestsigner
)
# Populate and verify the module cache before entering macOS confinement.
go mod download
go mod verify
# Retained upstream tests run as separate Go modules.
go -C third_party/btcec mod download
go -C third_party/btcec mod verify
go -C third_party/secp256k1 mod download
go -C third_party/secp256k1 mod verify
go -C third_party/chainhash mod download
go -C third_party/chainhash mod verify
go build -o "$fixture_bin/labcompose" ./tools/labcompose
go build -o "$fixture_bin/labownnode" ./tools/labownnode
go build -o "$fixture_bin/candidate-swarma-keyvault" ./cmd/swarma-keyvault
# Avoid a race-runtime exit sleep for every one-shot fake CLI call.
# The actual wrapper, bridge and protocol controls run in the race parent.
go test -c -o "$fixture_bin/fake-node-cli" ./lab/namecoinwrapper
for binary in swarma-keyvault labtestsigner labcompose labownnode candidate-swarma-keyvault fake-node-cli; do
  test -f "$fixture_bin/$binary" && test -x "$fixture_bin/$binary"
  test -O "$fixture_bin/$binary" && test ! -L "$fixture_bin/$binary"
done
export LAB_KEYVAULT_CLI="$fixture_bin/swarma-keyvault"
export LAB_CANDIDATE_KEYVAULT_CLI="$fixture_bin/candidate-swarma-keyvault"
export KEYVAULT_BIN="$LAB_KEYVAULT_CLI"
export LAB_TEST_SIGNER="$fixture_bin/labtestsigner"
export LAB_COMPOSE="$fixture_bin/labcompose"
export LAB_OWN_NODE="$fixture_bin/labownnode"
export LAB_NODE_FIXTURE_CLI="$fixture_bin/fake-node-cli"
# Permission-refusal controls intentionally create world-readable files.
umask 022
# macOS: inherit confinement before native startup.
scripts/keyvault-test-confined.sh -race -count=1 -v ./...
# Linux: use the same fixture exports and run instead:
# MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -race -count=1 -v ./...
```

The source clone needs the public base commit; a shallow candidate clone must
fetch that exact base first. The fixture bundle supplies the two additional
commits. See the [bundle inventory](../.github/fixtures/README.md) for provenance
and regeneration constraints. Retain `lab_root` while testing, then remove only
that scratch directory when no child uses it.

`labcompose INPUT` is the legacy Linux-only mode: `/proc` reopening preserves
inherited descriptors and status flags. Other platforms explicitly refuse it.
On Linux and macOS, `labcompose --owned-protocol INPUT` uses dedicated anonymous
pipes transferred exclusively by the supervisor. Cancellation is terminal in
both modes; it interrupts blocked reads, request writes and final writes.
The Mac suite exercises the owned mode and explicit legacy refusal. The Linux
suite additionally exercises the unchanged legacy reopening and flag contract.
Cross-builds and vet checks on macOS do not run Linux protocol tests; hosted
Linux CI must run those tests with the fixtures above.
