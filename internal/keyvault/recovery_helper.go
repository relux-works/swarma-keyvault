package keyvault

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Set only when building the vault after signing its paired helper. Neither
// environment variables nor a runtime helper-path option can replace this pin.
var recoveryHelperCDHash string

type execRecoveryHelper struct {
	path    string
	pin     string
	verify  func(int, []byte) error
	timeout time.Duration
}

func newRecoveryHelper() recoveryHelper {
	exe, err := os.Executable()
	if err != nil {
		return &execRecoveryHelper{}
	}
	return &execRecoveryHelper{path: filepath.Join(filepath.Dir(exe), "mac-keyvault-enclave"), pin: recoveryHelperCDHash, verify: verifyRecoveryCode, timeout: 2 * time.Minute}
}

func (h *execRecoveryHelper) call(request any, maxResponse int) ([]byte, error) {
	pin, err := hex.DecodeString(h.pin)
	if err != nil || (len(pin) != 20 && len(pin) != 32) || hex.EncodeToString(pin) != h.pin || h.verify == nil || !filepath.IsAbs(h.path) || h.timeout <= 0 {
		return nil, recoveryRefuse("helper_not_admitted")
	}
	if err := h.verify(0, nil); err != nil {
		return nil, recoveryRefuse("vault_not_hardened")
	}
	data, err := json.Marshal(request)
	if err != nil || len(data) > 32768 {
		return nil, recoveryRefuse("helper_protocol")
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.path, "--recovery-private")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, recoveryRefuse("helper_unavailable")
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, recoveryRefuse("helper_unavailable")
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, recoveryRefuse("helper_unavailable")
	}
	// The child has exec'd and is blocked on its request. Admission applies to
	// that actual PID/code, so a substituted executable never sees any request.
	if err := h.verify(cmd.Process.Pid, pin); err != nil {
		input.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, recoveryRefuse("helper_not_admitted")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	_, err = input.Write(header[:])
	if err == nil {
		_, err = input.Write(data)
	}
	_ = input.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, recoveryRefuse("helper_protocol")
	}
	var frame [5]byte
	_, err = io.ReadFull(output, frame[:])
	n := int(binary.BigEndian.Uint32(frame[1:]))
	limit := maxResponse
	if frame[0] == 1 {
		limit = 64
	}
	if err != nil || frame[0] > 1 || n < 1 || n > limit {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, recoveryRefuse("helper_protocol")
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(output, payload)
	var extra [1]byte
	more, last := output.Read(extra[:])
	exitErr := cmd.Wait()
	if err != nil || more != 0 || last != io.EOF || ctx.Err() != nil || (frame[0] == 0 && exitErr != nil) {
		clear(payload)
		return nil, recoveryRefuse("helper_protocol")
	}
	if frame[0] != 0 {
		clear(payload)
		return nil, recoveryRefuse("helper_refused")
	}
	return payload, nil
}

func (h *execRecoveryHelper) CreateWrap(purpose string) (recoveryWrap, error) {
	var result recoveryWrap
	if purpose != "nostr" && purpose != "namecoin" {
		return result, recoveryRefuse("invalid_purpose")
	}
	data, err := h.call(struct {
		Op      string `json:"op"`
		Purpose string `json:"purpose"`
	}{"create-wrap", purpose}, 24576)
	if err != nil {
		return result, err
	}
	return parseRecoveryWrap(data, purpose)
}

func parseRecoveryWrap(data []byte, purpose string) (recoveryWrap, error) {
	var result recoveryWrap
	if len(data) > 24576 || DecodeSingleJSON(data, &result) != nil || validateRecoveryWrap(result, purpose) != nil {
		return recoveryWrap{}, recoveryRefuse("wrapping_policy_refused")
	}
	// The paired helper emits sorted, slash-unescaped JSON. Re-encoding all
	// required fields also refuses omitted false, noncanonical base64 and keys.
	canonical, err := json.Marshal(map[string]any{"blob": result.Blob, "point": result.Point, "fingerprint": result.Fingerprint, "policy": result.Policy, "silent_refused": result.SilentRefused})
	if err != nil || !bytes.Equal(data, canonical) {
		return recoveryWrap{}, recoveryRefuse("wrapping_policy_refused")
	}
	return result, nil
}

func (h *execRecoveryHelper) UnwrapNostr(e recoveryEnvelope) ([]byte, error) {
	if e.Schema != "keyvault-enclave/1" || e.Algorithm != recoveryAlgorithm || len(e.EnclaveBlob) == 0 || len(e.EnclaveBlob) > 16384 || len(e.Ciphertext) != 149 || validateWrapping(e.Point, e.Fingerprint) != nil {
		return nil, recoveryRefuse("invalid_envelope")
	}
	data, err := h.call(struct {
		Op         string `json:"op"`
		Blob       []byte `json:"blob"`
		Point      []byte `json:"point"`
		Ciphertext []byte `json:"ciphertext"`
	}{"unwrap-nostr", e.EnclaveBlob, e.Point, e.Ciphertext}, 68)
	if err != nil {
		return nil, err
	}
	if len(data) != 68 {
		clear(data)
		return nil, recoveryRefuse("helper_protocol")
	}
	return data, nil
}

// A public fixture qualification response has no arbitrary private output.
func (h *execRecoveryHelper) qualify(purpose string, e recoveryEnvelope) error {
	data, err := h.call(struct {
		Op      string `json:"op"`
		Purpose string `json:"purpose"`
		Blob    []byte `json:"blob"`
		Point   []byte `json:"point"`
	}{"qualify-wrap", purpose, e.EnclaveBlob, e.Point}, 64)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, []byte("qualified")) {
		return recoveryRefuse("helper_protocol")
	}
	return nil
}
