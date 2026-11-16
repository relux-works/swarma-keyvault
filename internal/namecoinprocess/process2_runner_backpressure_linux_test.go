//go:build linux

package namecoinprocess

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: closing the owned fd5 writer on deadline interrupts one genuinely
// blocked kernel-pipe Write and joins it before Wait/Reap. Limit: Linux pipe
// resizing and the helper are local fixtures, not production identity proof.
func TestProcess2DeadlineClosesAndJoinsBlockedCustodyWriter(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "13")
	frame := process2FrameFixture(MaxEnvelopeBlobBytes)
	frame.Metadata.Service = strings.Repeat("s", Process2MaxServiceBytes)
	frame.Metadata.PhysicalAccount = options.AttemptInputs.Group
	frame.Metadata.Sidecar = bytes.Repeat([]byte{'s'}, Process2MaxSidecarBytes)
	frame.Metadata.Record = bytes.Repeat([]byte{'r'}, Process2MaxRecordBytes)
	var err error
	options.Frame, err = EncodeProcess2CustodyFrame(frame)
	if err != nil {
		t.Fatal("encode maximum bounded writer fixture", err)
	}
	if len(options.Frame) <= 4096 {
		t.Fatal("oversized fixture failed to exceed the deliberately bounded pipe")
	}
	options.custodyPipeCapacity = 4096
	options.Deadline = time.Now().Add(100 * time.Millisecond)
	outcome, evidence := runProcess2(context.Background(), command, options)
	assertUnknown(t, outcome)
	if !evidence.admitted || evidence.frameBytes >= evidence.frameLength || !evidence.writeErr ||
		!evidence.writerCloseOK || !evidence.writerJoined || !evidence.waitDone || !evidence.stdinCloseOK {
		t.Fatal("blocked fd5 writer did not reach the bounded close, join, and same-child reap path")
	}
}
