package main

import "testing"

// Published NIP-06 public keys pin both disagreement directions independently
// of the vault implementation; malformed/checksum-invalid input must refuse.
func TestPublishedAndNegativeReferenceControls(t *testing.T) {
	rows, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 || rows[0].Public != "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917" || rows[1].Public != "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573" {
		t.Fatal("published reference outputs changed")
	}
	if _, err := derive("invalid mnemonic"); err == nil {
		t.Fatal("invalid input accepted")
	}
	if _, err := derive("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"); err == nil {
		t.Fatal("bad checksum accepted")
	}
}
