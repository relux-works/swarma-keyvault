package grants

import (
	"crypto/sha256"
	"errors"
	"io"
)

const journalScanMaxBytes int64 = 64 << 20

var errJournalScanLimit = errors.New("journal scan byte limit exceeded")

type journalScan struct {
	frameCount uint64
	byteCount  int64
	lastDigest [sha256.Size]byte
}

type journalScanReader struct {
	reader  io.Reader
	failure error
}

func (r *journalScanReader) Read(p []byte) (int, error) {
	if r.failure != nil {
		return 0, r.failure
	}
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		// ReadFull can discard an error accompanying a full requested buffer.
		// Retain only its controlled class and refuse the entire scan below.
		r.failure = journalReadError(err)
	}
	return n, err
}

// scanJournalFrames checks an entire physical stream from genesis to boundary
// EOF. It returns no summary on any failure, including an incomplete tail.
// Bodies remain opaque; this neither reconstructs typed state nor authenticates
// the supplied epoch, a writer or a rollback witness. No repair is authorized.
// Memory retains one bounded frame at a time. The caller owns Reader cancellation
// and time bounds; the byte limit alone does not guarantee read progress.
func scanJournalFrames(reader io.Reader, epoch [sha256.Size]byte, byteLimit int64) (*journalScan, error) {
	if byteLimit <= 0 || byteLimit > journalScanMaxBytes {
		return nil, errJournalScanLimit
	}
	// One extra byte distinguishes exact-budget EOF from a hidden nonempty tail.
	// The admitted ceiling above keeps byteLimit+1 representable.
	observed := &journalScanReader{reader: reader}
	limited := &io.LimitedReader{R: observed, N: byteLimit + 1}
	want := journalFrameLink{sequence: 1, epoch: epoch}
	var summary journalScan
	for {
		frame, err := readJournalFrame(limited, want)
		if limited.N == 0 {
			return nil, errJournalScanLimit
		}
		if observed.failure != nil {
			return nil, observed.failure
		}
		if err == io.EOF {
			summary.byteCount = byteLimit + 1 - limited.N
			return &summary, nil
		}
		if err != nil {
			return nil, err
		}
		summary.frameCount++
		summary.lastDigest = frame.digest
		want.sequence++
		want.previous = frame.digest
	}
}
