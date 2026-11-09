# Explicit cryptographic source repairs

The root `go.mod` explicitly replaces these two modules with local source.
The existing signing, nonce derivation and precomputed base-multiplication
algorithms are retained. Both copies retain their upstream ISC licenses.

| Module | Version and upstream commit | Original module checksum |
| --- | --- | --- |
| `github.com/btcsuite/btcd/btcec/v2` | `v2.5.1`, [btcd/btcec e799ee427b65b7a6dbb59c8a2ad2bbf2027f7f39](https://github.com/btcsuite/btcd/tree/e799ee427b65b7a6dbb59c8a2ad2bbf2027f7f39/btcec) | `h1:zDnj4h0PTlFz69xIhoGGXYkkkYxPgTv/AfjBxQQLlnE=` |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | `v4.4.1`, [dcrd/dcrec/secp256k1 76c0dc4f362b89331ff3bd46a3527f904181b8e0](https://github.com/decred/dcrd/tree/76c0dc4f362b89331ff3bd46a3527f904181b8e0/dcrec/secp256k1) | `h1:5RVFMOWjMyRy8cARdy79nAmgYw3hK/4HUq48LQ6Wwqo=` |

The exact changes from those source versions are in
[`patches/cleanup.patch`](patches/cleanup.patch). The btcec module's local
replacement also applies when running its retained upstream tests directly.
This is an explicit source repair, not a modification of the Go module cache.

Named signing scalars, raw private encodings, secret-derived nonce hashes,
effective nonce/response intermediates, auxiliary input copies and the fast
base-multiplication encoding have explicit owners and cleanup on return.
Private serialization clears its value-receiver copy while transferring the
returned bytes to its caller. Retained RFC6979 signing also clears key/V/K
buffers, replaced HMAC outputs and reconstructible HMAC pads. Returned nonce
scalars transfer to the signer and are cleared there.

`schnorr.CustomNonce` options are **single-use** in this repair, so their captured
auxiliary input can be cleared after signing. Reuse, including concurrent reuse,
refuses instead of silently signing with erased input. The vault constructs a
fresh option from fresh OS randomness for each operation. Multiple fresh
options preserve last-option selection and erase overwritten auxiliary input.

These guarantees concern named mutable buffers on the ordinary Go Nostr paths.
The [buffer lifetime audit](BUFFER_LIFETIMES.md) identifies their owners,
return-path coverage and the distinction between observed tests and source audit.
They do not guarantee erasure of compiler/register copies, arithmetic or hash
implementation internals, GC/stack history or framework state. The original
variable-time characteristics remain; there is no constant-time or resistance
to local memory/side-channel inspection claim. TinyGo is not a supported vault
target; its alternative scalar traversal is not qualified by this repair.

Run the retained upstream tests and direct-buffer lifecycle tests with:

```
go -C third_party/btcec test -race -count=1 -timeout=10m ./...
go -C third_party/secp256k1 test -race -count=1 -timeout=10m ./...
```

The ordinary repository suite includes these commands through
`scripts/tests/TestCryptoRepairUpstream`. The root Nostr tests also cover every
official BIP-340 row, independently pinned auxiliary signatures, public-key
boundaries, independent public-point samples and refusal behavior. Test secrets
are synthetic/public fixtures and never represent a vault identity.

Use `-timeout=30m` for the parent repository suite. Each module command is bounded
at twelve minutes including build/setup, and each child test binary retains Go's
ten-minute timeout with native diagnostics. Both module commands finish before
verdicts are reported, including after a failure. The direct child is waited;
remaining members of its dedicated process group are killed and must disappear
within the bounded cleanup interval. Descendants that escape that group are
outside this test harness's contract. A cleanup refusal keeps the result nonzero.
Hosted Linux reserves forty minutes for setup, both bounded module commands and
cleanup. These execution budgets do not change the product's separate 100ms
verifier fence or measurement criteria. Per-module output, elapsed time and
startup/test/deadline/cleanup causes remain visible in the test log.
