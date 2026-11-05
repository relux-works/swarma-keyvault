package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Owner-root revocations (contract §2.4): signed by the grant root under
// Touch ID and installed out of band into every receiver's protected
// configuration, never delivered through the publisher. They win at any age.

type muRootRevocationSpec struct {
	Issuer   string                  `json:"issuer"`
	IssuedAt string                  `json:"issued_at"`
	Entries  []mugrant.SnapshotEntry `json:"entries"`
}

func runMURootRevocationPrepare(args []string, stdout, stderr io.Writer) int {
	path, code := muSpecArg("mu-root-revocation-prepare", args, stderr)
	if code >= 0 {
		return code
	}
	raw, err := readInput(path, nil, 16384)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded revocation specification")
		return 1
	}
	var s muRootRevocationSpec
	if err := muStrictJSON(raw, &s); err != nil {
		fmt.Fprintln(stderr, "revocation specification refused:", err)
		return 1
	}
	at, err := muTime(s.IssuedAt)
	if err != nil {
		fmt.Fprintln(stderr, "revocation time refused:", err)
		return 1
	}
	if len(s.Entries) == 0 {
		fmt.Fprintln(stderr, "revocation specification refused: an owner-root revocation names at least one entry")
		return 1
	}
	plan, err := mugrant.BuildSnapshot(s.Issuer, at, s.Entries)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	d := plan.Digest()
	lines := []string{"revocation/1 owner-root revocation, to be signed under Touch ID; it wins at any age", "issuer: " + s.Issuer, "issued at UTC: " + s.IssuedAt}
	for _, e := range s.Entries {
		lines = append(lines, "revokes: "+e.Kind+" "+e.ID+" from "+e.From)
	}
	lines = append(lines, "content id: "+plan.ContentID(), "signing digest: "+hex.EncodeToString(d[:]))
	return muWrite(stdout, map[string]string{
		"type": "mu-root-revocation-prepared-1", "kind": "revocation/1", "key": s.Issuer,
		"body": base64.RawURLEncoding.EncodeToString(plan.Body()), "content_id": plan.ContentID(),
		"digest_sha256": hex.EncodeToString(d[:]), "rendering": strings.Join(lines, "\n") + "\n",
	})
}
