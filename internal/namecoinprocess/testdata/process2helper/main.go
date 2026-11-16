// Package main is a public-data-only subprocess fixture for the portable
// process/2 adapter tests. It does not call native APIs or claim identity.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

//go:embed result.json
var result []byte

func main() {
	invocation, err := namecoinprocess.ParseProcess2Args(os.Args[1:])
	if err != nil {
		os.Exit(81)
	}
	args := invocation.Args()
	output := os.NewFile(3, "public-result-fixture")
	status := os.NewFile(4, "status-fixture")
	custody := os.NewFile(5, "custody-fixture")
	if output == nil || status == nil || custody == nil {
		os.Exit(82)
	}
	defer status.Close()
	defer custody.Close()
	if args.Timeout == 17*time.Second {
		os.Exit(89)
	}
	if args.Timeout == 13*time.Second {
		time.Sleep(time.Hour)
		return
	}

	frameBytes, err := io.ReadAll(io.LimitReader(custody, int64(namecoinprocess.Process2MaxCustodyFrameBytes+1)))
	if err != nil || len(frameBytes) > namecoinprocess.Process2MaxCustodyFrameBytes {
		os.Exit(83)
	}
	frame, err := namecoinprocess.DecodeProcess2CustodyFrame(frameBytes)
	if err != nil || frame.Metadata.PhysicalAccount != args.Group {
		os.Exit(84)
	}
	if args.Timeout == 14*time.Second {
		time.Sleep(time.Hour)
		return
	}
	if args.Timeout == 18*time.Second {
		if err := os.WriteFile(args.OutputPath+".pre-effect", []byte("held before effect"), 0o600); err != nil {
			os.Exit(92)
		}
		for {
			if _, err := os.Stat(args.OutputPath + ".continue"); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	binding := attemptBinding(args)
	started, err := namecoinprocess.EncodeProcess2StatusFrame(namecoinprocess.Process2StatusFrame{
		Event: namecoinprocess.Process2EffectStarted, AttemptBinding: binding,
	})
	if err != nil || writeOnce(status, started) != nil {
		os.Exit(85)
	}
	if args.Timeout == 11*time.Second {
		return
	}
	if args.Timeout == 18*time.Second {
		partialLength := len(result) / 2
		if writeOnce(output, result[:partialLength]) != nil || output.Sync() != nil {
			os.Exit(86)
		}
		if err := os.WriteFile(args.OutputPath+".partial", []byte("partial public result"), 0o600); err != nil {
			os.Exit(94)
		}
		for {
			if _, err := os.Stat(args.OutputPath + ".write-rest"); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if writeOnce(output, result[partialLength:]) != nil || output.Sync() != nil || output.Close() != nil {
			os.Exit(86)
		}
	} else if writeOnce(output, result) != nil || output.Sync() != nil || output.Close() != nil {
		os.Exit(86)
	}
	digest := sha256.Sum256(result)
	completed, err := namecoinprocess.EncodeProcess2StatusFrame(namecoinprocess.Process2StatusFrame{
		Event: namecoinprocess.Process2NativeCompleted, AttemptBinding: binding, ResultSHA256: digest,
	})
	if err != nil || writeOnce(status, completed) != nil {
		os.Exit(87)
	}
	ack := namecoinwire.Acknowledgement(digest)
	if args.Timeout == 12*time.Second {
		_, _ = os.Stderr.Write([]byte("fixture stderr violation\n"))
	}
	if writeOnce(os.Stdout, ack) != nil {
		os.Exit(88)
	}
	if args.Timeout == 18*time.Second {
		if err := os.WriteFile(args.OutputPath+".complete", []byte("completed after cancellation"), 0o600); err != nil {
			os.Exit(93)
		}
	}
	if args.Timeout == 15*time.Second {
		if status.Close() != nil || os.Stdout.Close() != nil || os.Stderr.Close() != nil {
			os.Exit(90)
		}
		if err := os.WriteFile(args.OutputPath+".eof", []byte("eof"), 0o600); err != nil {
			os.Exit(91)
		}
		for {
			if _, err := os.Stat(args.OutputPath + ".continue"); err == nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func writeOnce(file *os.File, value []byte) error {
	n, err := file.Write(value)
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	return nil
}

func attemptBinding(args namecoinprocess.Args) [32]byte {
	profile, _ := hex.DecodeString(args.ProfileSHA256)
	request, _ := hex.DecodeString(args.RequestSHA256)
	h := sha256.New()
	_, _ = h.Write([]byte("keyvault-namecoin-process-observation/1\x00"))
	for _, field := range [][]byte{[]byte("sign-psbt"), []byte(args.Group), []byte(args.Account), profile, request} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(field)
	}
	var binding [32]byte
	copy(binding[:], h.Sum(nil))
	return binding
}
