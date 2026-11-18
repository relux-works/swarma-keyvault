# Agent Nostr public fixture generator

This Go-only generator freezes deterministic, public test material for the
agent Nostr custody format. It reads the repository's pinned BIP340 CSV and
the checked public-encoding fixture. Its test-only P-256 wrapping scalars and
secp256k1 signing scalars come from published test inputs; they are never
production entropy or live credentials. The opaque fixture blobs are markers,
not Secure Enclave representations.

From the repository root, regenerate the files with:

```sh
go run ./tools/agentnostrfixture --write
```

Verify the independent generator and its checked-in bytes with:

```sh
go test ./tools/agentnostrfixture
```

The committed manifest records the BIP340 source revision and CSV digest, the
repository input baseline, the generator source digest, and byte counts and
SHA-256 digests for each fixture's metadata, enrollment receipt, envelope,
plaintext and ciphertext. The test-only sealer and decoder use separate code
paths; neither imports the production validator or seal/open routines. The
oracle checks AEAD and first-failing-predicate reachability. It does not prove
production guard behavior, native hardware origin, Keychain ACLs or UI policy.
