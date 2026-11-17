# Agent Nostr public fixtures

These files contain only public test inputs. Fixture A uses BIP340 vector row
0; fixture B uses row 1 and represents a complete valid replacement under the
same selector. The deep mutants preserve a valid 150-byte AEAD envelope and
69-byte plaintext length while violating one domain, binding, scalar-range or
public-key predicate.

The BIP340 CSV is pinned to `bitcoin/bips` revision
`200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb`, file
`bip-0340/test-vectors.csv`. The separate public-encoding fixture pins the
existing NIP19 example and P-256 generator point without a scalar or
ciphertext. None of these bytes is native custody or a real Secure Enclave
blob.

Run `go run ./tools/agentnostrfixture --write` to regenerate the deterministic
files, then `go test ./tools/agentnostrfixture` to compare them with the
committed goldens and verify their test-only cryptographic structure.
