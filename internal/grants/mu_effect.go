package grants

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrMUEffect refuses an effect request before or during execution.
var ErrMUEffect = errors.New("mu-effect-unavailable")

// muTitleLimit bounds the assigned task title in Unicode scalars.
const muTitleLimit = 120

// TaskBoardAssign is the work.assign effect (Meta Q-M5): it creates exactly
// one task element on the receiver's own board through a pinned task-board
// executable. It is real and reversible; it grants nothing else.
type TaskBoardAssign struct {
	Path, SHA256 string // pinned executable and its file digest
	BoardDir     string // absolute board directory of the receiver
	Parent       string // parent story for assigned tasks
}

func muTitle(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > muTitleLimit || strings.ContainsAny(s, "\"\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func muToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Execute creates one element and returns a JSON receipt. Any refusal before
// launch starts no process.
func (e TaskBoardAssign) Execute(ctx context.Context, d MUDecision) ([]byte, error) {
	if d.Action != "work.assign" || !muTitle(d.Arguments["title"]) || !muToken(d.Arguments["module"]) || !muToken(e.Parent) {
		return nil, ErrMUEffect
	}
	if !a2aAbsolutePath(e.BoardDir) || checkA2APinnedExecutable(e.Path, e.SHA256) != nil {
		return nil, ErrMUEffect
	}
	if !muContentID(d.GrantID) {
		return nil, ErrMUEffect
	}
	request := hex.EncodeToString(d.RequestHash[:])
	name := "granted-" + request[:12]
	description := fmt.Sprintf("Assigned under owner grant %s by %s, request sha256 %s, module %s: %s", muSafe(d.GrantID), muSafe(d.Author), request, d.Arguments["module"], d.Arguments["title"])
	dsl := fmt.Sprintf(`create(type=task, name=%q, parent=%s, description=%q)`, name, e.Parent, description)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Path, "--board-dir", e.BoardDir, "m", dsl)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, diag := &boundedLocalOutput{maximum: 65536}, &boundedLocalOutput{maximum: 8192}
	cmd.Stdout, cmd.Stderr = out, diag
	cmd.WaitDelay = subprocessWaitDelay
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return nil, ErrMUEffect
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.OK || !strings.HasPrefix(result.Result.ID, "TASK-") || len(result.Result.ID) > 64 {
		return nil, ErrMUEffect
	}
	if result.Result.Name != "" && result.Result.Name != name {
		return nil, ErrMUEffect
	}
	return json.Marshal(map[string]string{"type": "mu-work-assign-receipt/1", "element_id": result.Result.ID, "request_sha256": request})
}

// muSafe keeps identifiers DSL-safe inside a quoted description.
func muSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// muContentID admits only a platform content id: "sha256:" + 64 lowercase hex.
func muContentID(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
