// labownnode is a finite read-only supervisor for labcompose's existing pipe.
// Its independently installed route is a trusted local capability, not a claim
// taken from a certificate, request, RPC response or name record.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	wrapper "github.com/relux-works/swarma-keyvault/lab/namecoinwrapper"
)

const maxReply = 8 << 20

var refused = errors.New("own-node observation refused")

// Config is installed independently of the observation input. No argv, URL,
// shell command, credential or wallet option is accepted. NodeConfig contents
// remain in operator custody and are never read or exported by this program.
type Config struct {
	Network, Genesis        string
	NodeCLI, NodeCLISHA256  string
	NodeConfig, NodeDataDir string
	Compose, ComposeSHA256  string
	PrivateRoot             string
	// RouteID identifies the operator's separately admitted own-node route.
	// It is required but does not prove authentication, freshness or custody.
	RouteID string
}

func decodeConfig(raw []byte) (Config, error) {
	var c Config
	fields := map[string]*string{
		"Network": &c.Network, "Genesis": &c.Genesis, "NodeCLI": &c.NodeCLI,
		"NodeCLISHA256": &c.NodeCLISHA256, "NodeConfig": &c.NodeConfig,
		"NodeDataDir": &c.NodeDataDir, "Compose": &c.Compose,
		"ComposeSHA256": &c.ComposeSHA256, "PrivateRoot": &c.PrivateRoot, "RouteID": &c.RouteID,
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return c, refused
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		field := fields[key]
		if err != nil || !ok || field == nil || seen[key] {
			return c, refused
		}
		seen[key] = true
		var value any
		if d.Decode(&value) != nil {
			return c, refused
		}
		text, ok := value.(string)
		if !ok {
			return c, refused
		}
		*field = text
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') {
		return c, refused
	}
	if d.Decode(new(any)) != io.EOF || len(seen) != len(fields) {
		return c, refused
	}
	return c, nil
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, refused
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, refused
	}
	return b, nil
}

func absolute(path string, dir bool) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	s, err := os.Lstat(path)
	return err == nil && s.Mode()&os.ModeSymlink == 0 && s.IsDir() == dir && (dir || s.Mode().IsRegular())
}

func pinned(path, expected string) bool {
	if !absolute(path, false) || len(expected) != 64 {
		return false
	}
	s, err := os.Stat(path)
	if err != nil || s.Mode().Perm()&0111 == 0 {
		return false
	}
	b, err := readFile(path, 64<<20)
	return err == nil && digest(b) == expected
}

func (c Config) validate() error {
	network, genesis, err := wrapper.NetworkPolicy(c.Network, c.Genesis)
	if err != nil || c.Network != network || c.Genesis != genesis || c.RouteID == "" || len(c.RouteID) > 128 {
		return refused
	}
	if !pinned(c.NodeCLI, c.NodeCLISHA256) || !pinned(c.Compose, c.ComposeSHA256) ||
		!absolute(c.NodeConfig, false) || !absolute(c.NodeDataDir, true) || !absolute(c.PrivateRoot, true) {
		return refused
	}
	s, err := os.Stat(c.PrivateRoot)
	if err != nil || s.Mode().Perm() != 0700 {
		return refused
	}
	return nil
}

// Fixed options precede a closed method and JSON-encoded positional params.
// No value can become a credential/remote/wallet option or shell expression.
func nodeArgs(c Config, method string, params []json.RawMessage) ([]string, error) {
	switch method {
	case "getblockchaininfo", "getblockhash", "getblockheader", "name_show", "getrawtransaction", "gettxout", "getrawmempool", "getblock":
	default:
		return nil, refused
	}
	if len(params) > 3 {
		return nil, refused
	}
	args := []string{"-conf=" + c.NodeConfig, "-datadir=" + c.NodeDataDir, "-chain=" + c.Network, "-rpcclienttimeout=2", method}
	for _, raw := range params {
		if len(raw) > 4096 || !json.Valid(raw) {
			return nil, refused
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			// Namecoin CLI expects bare strings, JSON for objects/numbers/bools.
			if len(text) == 0 || text[0] == '-' {
				return nil, refused
			}
			args = append(args, text)
		} else {
			args = append(args, string(raw))
		}
	}
	return args, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, refused
	}
	return b.Buffer.Write(p)
}

func nodeCall(ctx context.Context, c Config, root, method string, params []json.RawMessage) (json.RawMessage, error) {
	args, err := nodeArgs(c, method, params)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.NodeCLI, args...)
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "XDG_CACHE_HOME=" + root, "PATH=/nonexistent", "LC_ALL=C"}
	cmd.Dir = root
	cmd.WaitDelay = time.Second
	out, diag := &boundedBuffer{limit: maxReply}, &boundedBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr = out, diag
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, refused
	}
	// Core's CLI prints a string result as bare text, not JSON. The closed
	// graph's string-returning method is getblockhash. Project that exact hash
	// into the existing pipe's JSON-result format; never JSON-guess arbitrary
	// output or reinterpret an error as a successful result.
	if method == "getblockhash" {
		text := strings.TrimSuffix(out.String(), "\n")
		decoded, err := hex.DecodeString(text)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != text {
			return nil, refused
		}
		raw, err := json.Marshal(text)
		return raw, err
	}
	// Core emits no stdout for a successful null result. Only gettxout has a
	// null success in this graph; preserving it is essential for spend controls.
	if method == "gettxout" && out.Len() == 0 {
		return json.RawMessage("null"), nil
	}
	if !json.Valid(out.Bytes()) {
		return nil, refused
	}
	return bytes.Clone(out.Bytes()), nil
}

type message struct {
	RPC    string            `json:"rpc"`
	Params []json.RawMessage `json:"params"`
	Done   bool              `json:"done"`
}

func run(ctx context.Context, c Config, inputPath string, output io.Writer) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("own-node composition requires Unix pollable pipes")
	}
	if c.validate() != nil || !absolute(inputPath, false) {
		return refused
	}
	input, err := readFile(inputPath, 65536)
	if err != nil {
		return err
	}
	var in struct {
		Mode    string
		Policy  wrapper.Policy
		Binding struct{ Chain, Genesis string }
	}
	if json.Unmarshal(input, &in) != nil {
		return refused
	}
	network, genesis, err := wrapper.NetworkPolicy(in.Policy.Network, in.Policy.Genesis)
	if err != nil || network != c.Network || genesis != c.Genesis {
		return refused
	}
	if in.Mode != "verify" && in.Mode != "watch" {
		return refused
	}
	if in.Mode == "watch" && (in.Binding.Chain != network || in.Binding.Genesis != genesis) {
		return refused
	}
	root, err := os.MkdirTemp(c.PrivateRoot, "own-node-")
	if err != nil {
		return refused
	}
	defer os.RemoveAll(root)
	// Freeze the exact input bytes checked above, rather than reopening a path
	// that an integrating caller could change after the policy comparison.
	frozen := filepath.Join(root, "input.json")
	if os.WriteFile(frozen, input, 0600) != nil {
		return refused
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	started := time.Now().UTC()
	// os/exec creates dedicated child pipe endpoints and closes its copies after
	// Start. Ownership transfer permits portable interruptible I/O in labcompose.
	cmd := exec.CommandContext(ctx, c.Compose, "--owned-protocol", frozen)
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "XDG_CACHE_HOME=" + root, "PATH=/nonexistent"}
	cmd.Dir = root
	cmd.WaitDelay = time.Second
	diag := &boundedBuffer{limit: 8192}
	cmd.Stderr = diag
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return refused
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return refused
	}
	if cmd.Start() != nil {
		stdin.Close()
		stdout.Close()
		return refused
	}
	defer func() { stdin.Close(); stdout.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxReply)
	encoder := json.NewEncoder(stdin)
	calls, total := 0, 0
	for scanner.Scan() {
		raw := bytes.Clone(scanner.Bytes())
		total += len(raw)
		if total > 64<<20 {
			return refused
		}
		var m message
		if json.Unmarshal(raw, &m) != nil {
			return refused
		}
		if m.Done {
			if m.RPC != "" {
				return refused
			}
			stdin.Close()
			if cmd.Wait() != nil || ctx.Err() != nil {
				return refused
			}
			return json.NewEncoder(output).Encode(map[string]any{
				"type": "own-node-lab-observation-1", "network": network, "genesis": genesis,
				"input_sha256": digest(input), "compose_sha256": c.ComposeSHA256, "node_cli_sha256": c.NodeCLISHA256,
				"started_at": started, "finished_at": time.Now().UTC(), "read_calls": calls,
				"effect_authorized": false, "node_route_qualified": false, "result": json.RawMessage(raw),
			})
		}
		if calls >= 256 {
			return refused
		}
		calls++
		reply, err := nodeCall(ctx, c, root, m.RPC, m.Params)
		total += len(reply)
		if total > 64<<20 {
			return refused
		}
		if encoder.Encode(map[string]any{"result": reply, "failed": err != nil}) != nil {
			return refused
		}
	}
	return refused
}

func main() {
	// Independent process lifetime also bounds startup and a blocked final
	// receipt sink. Normal contexts kill/reap children before this last cutoff.
	lifetime := time.AfterFunc(18*time.Second, func() { os.Exit(124) })
	defer lifetime.Stop()
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: labownnode ABSOLUTE_ROUTE_JSON ABSOLUTE_LABCOMPOSE_INPUT_JSON")
		os.Exit(2)
	}
	if !absolute(os.Args[1], false) {
		fmt.Fprintln(os.Stderr, "own-node route requires an absolute regular file")
		os.Exit(2)
	}
	raw, err := readFile(os.Args[1], 16384)
	var c Config
	if err == nil {
		c, err = decodeConfig(raw)
	}
	if err == nil {
		err = run(context.Background(), c, os.Args[2], os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "own-node observation refused; check independently installed route, exact pins, Unix dedicated pipes and bounded read availability")
		os.Exit(2)
	}
}
