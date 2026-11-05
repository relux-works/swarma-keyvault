# Historical MU journal fixture

Writer revision: `c0146d2610cf9d2ea277479d4afd64b720d63c4a` (the full
`c0146d26` commit). `generate_test.go` is a test-only driver copied into that
revision's `internal/grants` package. It invokes that revision's actual
`InitializeMUState`, `reserve`, and `absorbRevocations` implementations.
The generator does not encode frames itself or use the current writer.

All identifiers are synthetic. The fixed epoch is
`SHA256("mu-legacy-c0146d26-test-epoch")`; the binding is audience
`synthetic-mu-legacy-receiver`, grant root `p256:synthetic-legacy-root`.
There are no keys, wall-clock timestamps, receiver credentials, or real state.

The state files are `mu.journal` (995 bytes) and `mu.lock` (empty). The journal
has five frames, in order:

1. Activation (kind 1).
2. Once reservation (kind 2), nonce `synthetic-nonce-1`.
3. Until-expiry reservation (kind 2), nonce `synthetic-nonce-2`.
4. Legacy revocation (kind 5), record `synthetic-revoked-grant`.
5. Legacy revocation (kind 5), key `p256:synthetic-revoked-key`.

Both reservations are held without dispatch intent or outcome. Their requester
is `p256:synthetic-requester`, grant is `synthetic-reserved-grant`, action is
`work.assign`, and target is product `synthetic-product`. The request hashes
are `SHA256("synthetic-request/" + nonce)`.

SHA256:

```text
da363d7efd50da658578a30df608ed94d3e783480fffd63bc9c4e8d7774305fe  mu.journal
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  mu.lock
```

Reproduce offline with Go 1.26.10 installed on PATH and dependencies already
cached. Run from the candidate repository root. The output directory must not
exist; the driver refuses to overwrite one. The historical clone is disposable
and has only the added generator test.

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
export MAC_KEYVAULT_SKIP_KEYCHAIN=1
fixture_source=$(pwd -P)
fixture_work=$(mktemp -d "${TMPDIR:-/tmp}/mu-legacy-generate.XXXXXXXX")
git clone --no-hardlinks --no-checkout "$fixture_source" "$fixture_work/writer"
git -C "$fixture_work/writer" remote remove origin
git -C "$fixture_work/writer" checkout --detach c0146d2610cf9d2ea277479d4afd64b720d63c4a
cp "$fixture_source/internal/grants/testdata/mu-legacy-c0146d26/generate_test.go" \
  "$fixture_work/writer/internal/grants/zz_mu_legacy_generate_test.go"
(cd "$fixture_work/writer" && MU_LEGACY_FIXTURE_OUT="$fixture_work/state" \
  go test -p 2 -count=1 -run '^TestGenerateMULegacyC0146D26$' -v ./internal/grants)
sha256sum "$fixture_work/state/mu.journal" "$fixture_work/state/mu.lock"
cmp "$fixture_work/state/mu.journal" \
  "$fixture_source/internal/grants/testdata/mu-legacy-c0146d26/mu.journal"
cmp "$fixture_work/state/mu.lock" \
  "$fixture_source/internal/grants/testdata/mu-legacy-c0146d26/mu.lock"
```

Replay under current code:

```sh
go test -p 2 -race -count=1 -run '^TestMULegacyC0146D26Fixture' -v ./internal/grants
```

The replay test copies both files into a private directory with mode 0700 and
files mode 0600; checkout permissions are not state admission permissions.
It pins the journal checksum and frame sequence, verifies both reservations,
refuses both held nonces, applies both revocations with `ErrMURevoked`, and
checks that legacy entries acquire neither signer attribution nor a mark.
A publisher snapshot omitting them succeeds and records its own union and
mark; that behavior survives another reopen.

The corruption test flips the last checksum byte in a private copy and requires
`openMUState` to return `ErrMUState`. An additional development negative control
removes only the `case journalRevocation:` branch in `muState.replay` through a
temporary Go `-overlay`; the replay test must fail to open the historical state.
No production source change is part of this fixture.

These tests cover local journal accounting, not envelope verification or the
macOS Keychain. The confined macOS suite remains a separate KV check.
