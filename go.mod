module github.com/relux-works/swarma-keyvault

go 1.26.10

// Explicit source-pinned cleanup repairs; see third_party/README.md.
replace github.com/btcsuite/btcd/btcec/v2 => ./third_party/btcec

replace github.com/btcsuite/btcd/chainhash/v2 => ./third_party/chainhash

replace github.com/decred/dcrd/dcrec/secp256k1/v4 => ./third_party/secp256k1

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.1
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/relux-works/swarma-envelope v0.0.0-20261105191315-6c71e5226416
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/relux-works/swarma-registrar v0.0.0-20261023164451-5f44ebf3f788 // indirect
)
