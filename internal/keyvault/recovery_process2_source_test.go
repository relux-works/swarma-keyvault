package keyvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
)

// Public software fixtures prove selection, exact pair validation, projection
// and source-buffer clearing. No Keychain or Enclave operation is exercised.
func TestSelectedProcess2Projection(t *testing.T) {
	for _, name := range []string{"v2-equal-service", "v2-distinct-service"} {
		t.Run(name, func(t *testing.T) {
			in := readRecoveryProcess2Fixture(t, name)
			pair := bytes.Clone(in.Pair)
			reads := 0
			frame, err := projectSelectedRecoveryProcess2(context.Background(), in.Selection, in.AccountPin,
				func(_ context.Context, group string, hash [32]byte) ([]byte, []byte, error) {
					reads++
					if group != in.Selection.Selection.Group || hash != in.Selection.Sidecar.MetadataHash {
						t.Fatal("wrong selected item")
					}
					return in.Record, pair, nil
				})
			if err != nil || reads != 1 {
				t.Fatal("projection", err, reads)
			}
			decoded, err := namecoinprocess.DecodeProcess2CustodyFrame(frame)
			if err != nil || decoded.Metadata.PhysicalAccount != in.Selection.Selection.Group {
				t.Fatal("frame", err)
			}
			if !bytes.Equal(pair, make([]byte, len(pair))) {
				t.Fatal("source pair retained")
			}
			if bytes.Equal(in.Pair, pair) {
				t.Fatal("immutable fixture changed")
			}
		})
	}
}

func TestSelectedProcess2ProjectionRefusesBeforeRead(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancel", "pin", "group", "account", "policy", "schema"} {
		t.Run(mode, func(t *testing.T) {
			in := readRecoveryProcess2Fixture(t, "v2-distinct-service")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var selectedContext context.Context = ctx
			switch mode {
			case "nil-context":
				selectedContext = nil
			case "cancel":
				cancel()
			case "pin":
				in.AccountPin[0] ^= 1
			case "group":
				in.Selection.Selection.Group = "other/recovery@1"
			case "account":
				in.Selection.Selection.Account = "other/namecoin@1"
			case "policy":
				in.Selection.Selection.Policy.Revision = "other/1"
			case "schema":
				in.Selection.Schema = "other/1"
			}
			frame, err := projectSelectedRecoveryProcess2(selectedContext, in.Selection, in.AccountPin,
				func(context.Context, string, [32]byte) ([]byte, []byte, error) {
					t.Fatal("unexpected read")
					return nil, nil, nil
				})
			if err == nil || len(frame) != 0 {
				t.Fatal("invalid selection released a frame")
			}
		})
	}
}

func TestSelectedProcess2ReadFailureAndLateCancelClearPair(t *testing.T) {
	for _, mode := range []string{"error", "cancel", "corrupt-pair", "wrong-record"} {
		t.Run(mode, func(t *testing.T) {
			in := readRecoveryProcess2Fixture(t, "v2-distinct-service")
			pair := bytes.Clone(in.Pair)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			frame, err := projectSelectedRecoveryProcess2(ctx, in.Selection, in.AccountPin,
				func(context.Context, string, [32]byte) ([]byte, []byte, error) {
					switch mode {
					case "error":
						return in.Record, pair, errors.New("source refused")
					case "cancel":
						cancel()
					case "corrupt-pair":
						pair[0] ^= 1
					case "wrong-record":
						return []byte("{}"), pair, nil
					}
					return in.Record, pair, nil
				})
			if err == nil || len(frame) != 0 || !bytes.Equal(pair, make([]byte, len(pair))) {
				t.Fatal("failed source released or retained custody")
			}
		})
	}
}

// The injected verifier proves synchronous handle/pin routing and cancellation
// checks only. Native code identity remains a separate platform lane.
func TestProcess2ChildAdmissionUsesFullBuildPin(t *testing.T) {
	for _, size := range []int{20, 32} {
		pin := strings.Repeat("ab", size)
		calls := 0
		err := admitNamecoinProcess2Child(context.Background(), &os.Process{Pid: 123}, pin, func(pid int, hash []byte) error {
			calls++
			if pid != 123 || hex.EncodeToString(hash) != pin {
				t.Fatal("child or full build pin changed")
			}
			return nil
		})
		if err != nil || calls != 1 {
			t.Fatal("valid admission seam", err, calls)
		}
	}
	for _, mode := range []string{"nil-context", "cancel", "nil-child", "invalid-pid", "missing-pin", "short-pin", "noncanonical-pin", "mismatch", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var admissionContext context.Context = ctx
			child, pin := &os.Process{Pid: 123}, strings.Repeat("ab", 20)
			switch mode {
			case "nil-context":
				admissionContext = nil
			case "cancel":
				cancel()
			case "nil-child":
				child = nil
			case "invalid-pid":
				child.Pid = 0
			case "missing-pin":
				pin = ""
			case "short-pin":
				pin = "ab"
			case "noncanonical-pin":
				pin = strings.ToUpper(pin)
			}
			calls := 0
			err := admitNamecoinProcess2Child(admissionContext, child, pin, func(int, []byte) error {
				calls++
				if mode == "late-cancel" {
					cancel()
					return nil
				}
				return errors.New("identity mismatch")
			})
			want := 0
			if mode == "mismatch" || mode == "late-cancel" {
				want = 1
			}
			if err == nil || calls != want {
				t.Fatal("admission escaped refusal", err, calls)
			}
		})
	}
}
