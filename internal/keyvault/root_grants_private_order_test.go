package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Every adjacent root/pair key swap is rejected as invalid_arguments beside
// valid retained-schema controls. These public constructor tests exercise no
// terminal, private derivation, native helper or custody operation.
func TestRootGrantsPrivateCanonicalAdjacentOrder(t *testing.T) {
	rootOrder := []string{"protocol", "engine", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"}
	// Literal contract order is independent of the production request type.
	pairOrder := []string{"schema", "service", "version", "group_id", "metadata_sha256", "nostr_identity", "nostr_version", "nostr_public_key", "nostr_npub", "namecoin_identity", "namecoin_version", "namecoin_xpub", "namecoin_origin"}
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			valid := rootGrantsRequest44(t, schema)
			session, err := OpenRootGrantsPrivate(context.Background(), valid)
			if err != nil || session == nil {
				t.Fatal("valid canonical control refused")
			}
			session.Close()
			var root, pair map[string]json.RawMessage
			if json.Unmarshal(valid, &root) != nil || json.Unmarshal(root["pair"], &pair) != nil {
				t.Fatal("public fixture malformed")
			}
			if len(root) != len(rootOrder) || len(pair) != len(pairOrder) {
				t.Fatal("literal key inventory differs from contract fixture")
			}
			if !bytes.Equal(rootGrantsObject44(t, root, rootOrder), valid) || !bytes.Equal(rootGrantsObject44(t, pair, pairOrder), root["pair"]) {
				t.Fatal("literal canonical positive order mismatch")
			}
			for _, level := range []string{"root", "pair"} {
				order := rootOrder
				if level == "pair" {
					order = pairOrder
				}
				for i := 0; i+1 < len(order); i++ {
					t.Run(level+"/"+order[i]+"-"+order[i+1], func(t *testing.T) {
						swapped := append([]string(nil), order...)
						swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
						var raw []byte
						if level == "root" {
							raw = rootGrantsObject44(t, root, swapped)
						} else {
							changed := make(map[string]json.RawMessage, len(root))
							for key, value := range root {
								changed[key] = value
							}
							changed["pair"] = rootGrantsObject44(t, pair, swapped)
							raw = rootGrantsObject44(t, changed, rootOrder)
						}
						if bytes.Equal(raw, valid) || !json.Valid(raw) {
							t.Fatal("ordering witness is not a distinct valid JSON object")
						}
						got, err := OpenRootGrantsPrivate(context.Background(), raw)
						if got != nil {
							got.Close()
							t.Fatal("noncanonical order created a session")
						}
						if err == nil || err.Error() != recoveryRefuse("invalid_arguments").Error() {
							t.Fatalf("wrong order did not return fixed invalid_arguments: %v", err)
						}
					})
				}
			}
		})
	}
}
