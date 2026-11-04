package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var errLocalProvider = errors.New("local provider outcome unavailable")

// ErrLocalProviderUnavailable refuses a known unusable provider path before a
// reservation. It does not describe a failure after durable dispatch intent.
var ErrLocalProviderUnavailable = errors.New("local provider executable unavailable")

// Check metadata without starting a process or probing provider credentials.
// This does not prevent same-UID replacement or prove ACL/format eligibility.
func checkLocalProviderExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return ErrLocalProviderUnavailable
	}
	return nil
}

const localReceiptLimit = 65536

type localProviderReceipt struct {
	raw    []byte
	id     uint64
	nodeID string
}

// GitHub returns many additional fields, whitespace and nested objects. Admit
// those legitimate JSON forms while rejecting duplicate members, excessive
// depth/tokens and ambiguous types in the four required receipt fields.
func parseLocalProviderReceipt(raw []byte) (*localProviderReceipt, error) {
	return parseRepositoryProviderReceipt(raw, LocalRepository)
}

func parseRepositoryProviderReceipt(raw []byte, repository string) (*localProviderReceipt, error) {
	if repository != LocalRepository && repository != A2ARepository {
		return nil, errLocalProvider
	}
	if len(raw) == 0 || len(raw) > localReceiptLimit {
		return nil, errLocalProvider
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		tokens++
		if depth > 12 || tokens > 8192 {
			return nil, errLocalProvider
		}
		token, err := d.Token()
		if err != nil {
			return nil, errLocalProvider
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				object := map[string]any{}
				for d.More() {
					tokens++
					if tokens > 8192 {
						return nil, errLocalProvider
					}
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || len(name) > 1024 {
						return nil, errLocalProvider
					}
					if _, ok := object[name]; ok {
						return nil, errLocalProvider
					}
					value, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					object[name] = value
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, errLocalProvider
				}
				return object, nil
			case '[':
				for d.More() {
					if _, err := read(depth + 1); err != nil {
						return nil, err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, errLocalProvider
				}
				return []any{}, nil
			default:
				return nil, errLocalProvider
			}
		}
		return token, nil
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errLocalProvider
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errLocalProvider
	}
	number, ok := object["id"].(json.Number)
	if !ok {
		return nil, errLocalProvider
	}
	id, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil || id == 0 {
		return nil, errLocalProvider
	}
	node, ok := object["node_id"].(string)
	if !ok || node == "" || len(node) > 1024 {
		return nil, errLocalProvider
	}
	for _, c := range node {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_-/+=", c)) {
			return nil, errLocalProvider
		}
	}
	if name, ok := object["full_name"].(string); !ok || name != LocalOrganization+"/"+repository {
		return nil, errLocalProvider
	}
	if private, ok := object["private"].(bool); !ok || !private {
		return nil, errLocalProvider
	}
	return &localProviderReceipt{raw: bytes.Clone(raw), id: id, nodeID: node}, nil
}

type localProvider interface {
	create(context.Context, *checkedLocalCreate) ([]byte, error)
}

type boundedLocalOutput struct {
	buffer  bytes.Buffer
	maximum int
}

func (b *boundedLocalOutput) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.buffer.Len() {
		return 0, errLocalProvider
	}
	return b.buffer.Write(p)
}

func (b *boundedLocalOutput) Bytes() []byte { return b.buffer.Bytes() }

type localGHProvider struct{ path string }

// All failure modes after intent are conservatively UNKNOWN, including a start
// failure. Nothing retries, probes for existence or dispatches a DELETE.
func (p localGHProvider) create(ctx context.Context, checked *checkedLocalCreate) ([]byte, error) {
	if checked == nil || checked.request == nil || checked.request.action != "repository.create" {
		return nil, errLocalProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	target := checked.request.createTarget
	if target.organization != LocalOrganization || target.name != LocalRepository || target.visibility != "private" {
		return nil, errLocalProvider
	}
	input, err := json.Marshal(map[string]any{"name": target.name, "private": true})
	if err != nil {
		return nil, errLocalProvider
	}
	command := exec.CommandContext(ctx, p.path, "api", "--hostname", "github.com", "-X", "POST", "orgs/"+target.organization+"/repos", "--input", "-")
	command.Stdin = bytes.NewReader(input)
	command.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	stdout := &boundedLocalOutput{maximum: localReceiptLimit}
	stderr := &boundedLocalOutput{maximum: 8192}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, errLocalProvider
	}
	return bytes.Clone(stdout.Bytes()), nil
}
