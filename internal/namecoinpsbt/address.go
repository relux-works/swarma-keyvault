package namecoinpsbt

import (
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Core28 chain parameters use nc on mainnet and ncrt on regtest. Address
// rendering refers to the decoded destination after the verified name prefix;
// review separately retains the complete name-bearing output script.
func witnessAddress(network string, program [20]byte) (string, error) {
	var hrp string
	switch network {
	case "namecoin-mainnet":
		hrp = "nc"
	case "namecoin-regtest":
		hrp = "ncrt"
	default:
		return "", failure(namecoinwire.PolicyRefused)
	}
	data, err := bech32.ConvertBits(program[:], 8, 5, true)
	if err != nil {
		return "", failure(namecoinwire.UnsupportedScript)
	}
	address, err := bech32.Encode(hrp, append([]byte{0}, data...))
	if err != nil {
		return "", failure(namecoinwire.UnsupportedScript)
	}
	return address, nil
}
