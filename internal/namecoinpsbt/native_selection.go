package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// NativeSelection is public, independently pinned local custody configuration.
// It must come from the qualified native adapter's selected setup, never the
// transaction request. Decode checks representation, not provenance or owner
// consent; the adapter must verify actual selected item/code identity and pins.
type NativeSelection struct {
	Schema    string                  `json:"schema"`
	Selection Selection               `json:"selection"`
	Sidecar   namecoinjournal.Sidecar `json:"sidecar"`
}

func DecodeNativeSelection(raw []byte) (NativeSelection, error) {
	var config NativeSelection
	if len(raw) == 0 || len(raw) > 4<<20 {
		return config, failure(namecoinwire.PolicyRefused)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.Schema != "keyvault-namecoin-native-selection/1" {
		return NativeSelection{}, failure(namecoinwire.PolicyRefused)
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, raw) {
		return NativeSelection{}, failure(namecoinwire.PolicyRefused)
	}
	if _, err = namecoinjournal.EncodeSidecar(config.Sidecar); err != nil {
		return NativeSelection{}, failure(namecoinwire.AccountMismatch)
	}
	var pin [32]byte
	if len(config.Selection.AccountPinSHA256) != 64 {
		return NativeSelection{}, failure(namecoinwire.AccountMismatch)
	}
	if _, err := hex.Decode(pin[:], []byte(config.Selection.AccountPinSHA256)); err != nil {
		return NativeSelection{}, failure(namecoinwire.AccountMismatch)
	}
	binding := config.Sidecar.Binding
	if binding.Group != config.Selection.Group || binding.Account != config.Selection.Account || binding.PublicPin != pin || binding.Policy != config.Selection.Policy.Revision {
		return NativeSelection{}, failure(namecoinwire.AccountMismatch)
	}
	return config, nil
}

// SelectNativeProfile checks the separately retained exact public file hash
// before decoding configuration. The expected hash comes from the trusted
// rollout/owner selection, never the request or a hash embedded in that file.
// This proves selected-byte consistency, not the trustworthiness of its source.
func SelectNativeProfile(raw []byte, expectedSHA256 string) (NativeSelection, error) {
	var expected [32]byte
	if len(raw) == 0 || len(raw) > 4<<20 || len(expectedSHA256) != 64 {
		return NativeSelection{}, failure(namecoinwire.PolicyRefused)
	}
	if _, err := hex.Decode(expected[:], []byte(expectedSHA256)); err != nil || hex.EncodeToString(expected[:]) != expectedSHA256 {
		return NativeSelection{}, failure(namecoinwire.PolicyRefused)
	}
	if sha256.Sum256(raw) != expected {
		return NativeSelection{}, failure(namecoinwire.PolicyRefused)
	}
	return DecodeNativeSelection(raw)
}
