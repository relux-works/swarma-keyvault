package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// runMURevocationPublish is the grant revocation publisher job (contract r5
// option A). Each cycle it builds a complete revocation/1 snapshot from the
// entries file, has the pinned installed mac-keyvault sign its digest with
// the publisher key (no user presence), assembles and verifies the envelope,
// and atomically replaces the output file. A failed cycle writes nothing; the
// receiver then refuses once the last snapshot is older than 60 s.
func runMURevocationPublish(args []string, stdout, stderr io.Writer) int {
	usageText := "swarma-keyvault grants mu-revocation-publish --publisher KEY_ID --signer SERVICE/PURPOSE --keyvault PATH --keyvault-sha256 HEX --entries FILE --out FILE --interval DURATION [--once]"
	f := flag.NewFlagSet("mu-revocation-publish", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var publisher, signer, keyvault, keyvaultSHA, entries, out, interval onceString
	once := f.Bool("once", false, "publish one snapshot and exit")
	for name, v := range map[string]*onceString{"publisher": &publisher, "signer": &signer, "keyvault": &keyvault, "keyvault-sha256": &keyvaultSHA, "entries": &entries, "out": &out, "interval": &interval} {
		f.Var(v, name, name)
	}
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, usageText)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	every, err := time.ParseDuration(interval.value)
	if f.NArg() != 0 || !publisher.set || !signer.set || !keyvault.set || !keyvaultSHA.set || !entries.set || !out.set || !interval.set || err != nil || every < time.Second || every > 60*time.Second || !filepath.IsAbs(out.value) {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	for {
		if err := muPublishOnce(publisher.value, signer.value, keyvault.value, keyvaultSHA.value, entries.value, out.value, stdout); err != nil {
			fmt.Fprintln(stderr, "snapshot not published:", err)
			if *once {
				return 1
			}
		} else if *once {
			return 0
		}
		time.Sleep(every)
	}
}

func muPublishOnce(publisher, signer, keyvault, keyvaultSHA, entriesPath, out string, stdout io.Writer) error {
	raw, err := readInput(entriesPath, nil, 65536)
	if err != nil {
		return errors.New("entries unavailable")
	}
	var entries []mugrant.SnapshotEntry
	if err := muStrictJSON(raw, &entries); err != nil {
		return fmt.Errorf("entries refused: %w", err)
	}
	plan, err := mugrant.BuildSnapshot(publisher, time.Now().UTC().Truncate(time.Second), entries)
	if err != nil {
		return err
	}
	if err := grants.CheckPinnedExecutable(keyvault, keyvaultSHA); err != nil {
		return errors.New("keyvault executable refused")
	}
	dir := filepath.Dir(out)
	sigFile, err := os.CreateTemp(dir, ".snapshot-sig-*")
	if err != nil {
		return errors.New("signature scratch unavailable")
	}
	sigPath := sigFile.Name()
	sigFile.Close()
	os.Remove(sigPath) // mac-keyvault creates the output file itself
	defer os.Remove(sigPath)
	d := plan.Digest()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyvault, "sign", signer, "--digest", hex.EncodeToString(d[:]), "--format", "ecdsa-der-low-s", "--out", sigPath)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return errors.New("keyvault sign failed")
	}
	der, err := readInput(sigPath, nil, 72)
	if err != nil {
		return errors.New("signature unavailable")
	}
	wire, err := mugrant.AssembleNative(plan, der)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return errors.New("output scratch unavailable")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(wire); err != nil || tmp.Chmod(0600) != nil || tmp.Sync() != nil || tmp.Close() != nil {
		tmp.Close()
		return errors.New("output write failed")
	}
	if err := os.Rename(tmpPath, out); err != nil {
		return errors.New("output replace failed")
	}
	if muWrite(stdout, map[string]any{"type": "mu-snapshot-published-1", "content_id": plan.ContentID(), "entries": len(entries)}) != 0 {
		return errors.New("status write failed")
	}
	return nil
}
