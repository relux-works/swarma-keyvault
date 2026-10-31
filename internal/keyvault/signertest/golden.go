// Package signertest loads the signer-v1 golden corpus
// (internal/keyvault/testdata/signer-v1) for the two suites that drive it
// through production: the keyvault package (SignerServer.Serve over a
// canned backend, one session per store shape) and the CLI package
// (run(signer serve ...), the startup hello). One loader keeps the
// fixture format and the corpus enumeration identical on both sides.
package signertest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// Dir is the corpus directory relative to internal/keyvault.
const Dir = "testdata/signer-v1"

// StartupSession names the fixtures the CLI package drives: each carries
// Args for `mac-keyvault <args...>` and the one hello line plus exit code
// the production entry point must produce.
const StartupSession = "startup"

// MaterialFile holds the canned key material and is not a fixture.
const MaterialFile = "fixture-key.json"

// Fixture is one <session>-<NN>-<name>.json. A server fixture carries the
// request line (Request, or RequestRaw for a line that is not JSON) and the
// exact response line; a fixture without a request is its session's hello.
// A startup fixture carries Args and Exit instead of a request, and
// optionally Setup, the name of an environment the CLI suite arranges
// before running (the lock path being unavailable, for instance).
type Fixture struct {
	Session    string          `json:"session"`
	Note       string          `json:"note"`
	Args       []string        `json:"args,omitempty"`
	Exit       *int            `json:"exit,omitempty"`
	Setup      string          `json:"setup,omitempty"`
	Request    json.RawMessage `json:"request,omitempty"`
	RequestRaw *string         `json:"request_raw,omitempty"`
	Response   *string         `json:"response"`
	Path       string          `json:"-"`
}

// IsHello reports whether the fixture is a session's hello line.
func (f Fixture) IsHello() bool { return f.Request == nil && f.RequestRaw == nil && f.Args == nil }

// RequestLine is the exact bytes sent for a server fixture: the compacted
// object, or RequestRaw verbatim.
func (f Fixture) RequestLine() ([]byte, error) {
	if f.RequestRaw != nil {
		return []byte(*f.RequestRaw), nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, f.Request); err != nil {
		return nil, fmt.Errorf("%s: request is not JSON: %w", f.Path, err)
	}
	return compact.Bytes(), nil
}

// ErrorCode returns the code of the fixture's recorded error response, or
// "" for a successful response.
func (f Fixture) ErrorCode() (string, error) {
	if f.Response == nil {
		return "", fmt.Errorf("%s: no response recorded", f.Path)
	}
	var resp signerclient.Response
	if err := json.Unmarshal([]byte(*f.Response), &resp); err != nil {
		return "", fmt.Errorf("%s: %w", f.Path, err)
	}
	if resp.Error == nil {
		return "", nil
	}
	return resp.Error.Code, nil
}

// Load reads every fixture under dir grouped by session, each session in
// file order. A file whose name does not start with its session, or a
// fixture that mixes Args with a request, is an error.
func Load(dir string) (map[string][]Fixture, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	fixtures := map[string][]Fixture{}
	for _, path := range paths {
		if filepath.Base(path) == MaterialFile {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var fixture Fixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		fixture.Path = path
		if !strings.HasPrefix(filepath.Base(path), fixture.Session+"-") {
			return nil, fmt.Errorf("%s: file name does not start with its session %q", path, fixture.Session)
		}
		if (fixture.Session == StartupSession) != (fixture.Args != nil) {
			return nil, fmt.Errorf("%s: only and every %s fixture carries args", path, StartupSession)
		}
		if fixture.Args != nil && (fixture.Request != nil || fixture.RequestRaw != nil || fixture.Exit == nil) {
			return nil, fmt.Errorf("%s: a startup fixture carries args and exit, no request", path)
		}
		fixtures[fixture.Session] = append(fixtures[fixture.Session], fixture)
	}
	return fixtures, nil
}

// Save rewrites the fixture file with response set to line (the -update
// path of the golden suites).
func Save(f Fixture, line string) error {
	f.Response = &line
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return err
	}
	return os.WriteFile(f.Path, data.Bytes(), 0o644)
}

// ErrorCodes returns every distinct error code the corpus records, with
// the fixture files that carry each, split into the codes the startup
// session carries and the codes the server sessions carry.
func ErrorCodes(fixtures map[string][]Fixture) (startup, server map[string][]string, err error) {
	startup, server = map[string][]string{}, map[string][]string{}
	for session, list := range fixtures {
		for _, f := range list {
			code, err := f.ErrorCode()
			if err != nil {
				return nil, nil, err
			}
			if code == "" {
				continue
			}
			target := server
			if session == StartupSession {
				target = startup
			}
			target[code] = append(target[code], filepath.Base(f.Path))
		}
	}
	return startup, server, nil
}
