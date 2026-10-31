package grants

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type subobjectCase struct {
	name  string
	valid map[string]any
	check func(*wireValue) error
}

func subobjectCases(t *testing.T) []subobjectCase {
	t.Helper()
	return []subobjectCase{
		{"audience", map[string]any{"deployment_id": "deploy-A", "executor_id": "exec-A"}, func(n *wireValue) error {
			v, e := parseAudienceNode(n)
			if e != nil && v != nil {
				t.Fatal("partial audience")
			}
			return e
		}},
		{"cycle", map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}, func(n *wireValue) error {
			v, e := parseCycleNode(n)
			if e != nil && v != nil {
				t.Fatal("partial cycle")
			}
			return e
		}},
		{"use", map[string]any{"cycle_id": "codex-dm", "operation_use_id": "codex-dm/create"}, func(n *wireValue) error {
			v, e := parseUseNode(n)
			if e != nil && v != nil {
				t.Fatal("partial use")
			}
			return e
		}},
		{"create", map[string]any{"organization": "Org.A", "name": "Repo_A", "visibility": "private"}, func(n *wireValue) error {
			v, e := parseCreateTargetNode(n)
			if e != nil && v != nil {
				t.Fatal("partial create")
			}
			return e
		}},
		{"delete-grant", map[string]any{"organization": "Org.A", "name": "Repo_A", "paired_create_entry": "repo-create"}, func(n *wireValue) error {
			v, e := parseDeleteGrantTargetNode(n)
			if e != nil && v != nil {
				t.Fatal("partial delete grant")
			}
			return e
		}},
		{"delete-request", map[string]any{"organization": "Org.A", "name": "Repo_A", "repository_id": "18446744073709551615", "create_operation_use_id": "codex-dm/create", "create_result_digest": strings.Repeat("a", 64)}, func(n *wireValue) error {
			v, e := parseDeleteRequestTargetNode(n)
			if e != nil && v != nil {
				t.Fatal("partial delete request")
			}
			return e
		}},
	}
}
func subobjectNode(t *testing.T, value any) *wireValue {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	n, e := parseCanonical(raw, certificateWire)
	if e != nil {
		t.Fatal("fixture lexical failure", e)
	}
	return n
}
func subobjectCopy(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Each field of all six subobjects is required and string-typed; canonical
// extras and wrong root types refuse schema with no partially usable result.
func TestPayloadSubobjectsClosedFields(t *testing.T) {
	for _, c := range subobjectCases(t) {
		positive := func() {
			t.Helper()
			if e := c.check(subobjectNode(t, c.valid)); e != nil {
				t.Fatal(c.name, "valid", e)
			}
		}
		positive()
		if e := c.check(nil); !errors.Is(e, errBadSchema) {
			t.Fatal(c.name, "nil node", e)
		}
		positive()
		for field := range c.valid {
			for _, mode := range []string{"missing", "integer", "boolean", "array", "object"} {
				t.Run(c.name+"/"+field+"/"+mode, func(t *testing.T) {
					positive()
					v := subobjectCopy(c.valid)
					switch mode {
					case "missing":
						delete(v, field)
					case "integer":
						v[field] = 1
					case "boolean":
						v[field] = true
					case "array":
						v[field] = []any{}
					case "object":
						v[field] = map[string]any{}
					}
					if e := c.check(subobjectNode(t, v)); !errors.Is(e, errBadSchema) {
						t.Fatal("wrong schema refusal", e)
					}
					positive()
				})
			}
		}
		v := subobjectCopy(c.valid)
		v["extra"] = true
		if e := c.check(subobjectNode(t, v)); !errors.Is(e, errBadSchema) {
			t.Fatal(c.name, "extra", e)
		}
		positive()
		for _, root := range []any{true, 1, "object", []any{}} {
			if e := c.check(subobjectNode(t, root)); !errors.Is(e, errBadSchema) {
				t.Fatal(c.name, "root", e)
			}
			positive()
		}
	}
}

// Exact allowed tags and individual ID/digest/decimal representations are
// checked without normalizing or asserting any enrollment or provider fact.
func TestPayloadSubobjectsFieldValues(t *testing.T) {
	for _, c := range subobjectCases(t) {
		for field, value := range c.valid {
			original := value.(string)
			invalid := []string{}
			switch field {
			case "runtime":
				invalid = []string{"Codex", "claude ", "other", ""}
			case "channel":
				invalid = []string{"dm", "encrypted-DM", "public-group", ""}
			case "visibility":
				invalid = []string{"public", "Private", "", "internal"}
			case "repository_id":
				invalid = []string{"0", "01", "+1", "-1", "18446744073709551616", "1e3", ""}
			case "create_result_digest":
				invalid = []string{strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), ""}
			case "organization", "name":
				continue // Ordinary exact text is not a provider-name validator.
			default:
				invalid = []string{"", "_id", "bad id", "id+alias"}
			}
			for _, bad := range invalid {
				t.Run(c.name+"/"+field+"/"+bad, func(t *testing.T) {
					if e := c.check(subobjectNode(t, c.valid)); e != nil {
						t.Fatal("valid before", e)
					}
					v := subobjectCopy(c.valid)
					v[field] = bad
					if e := c.check(subobjectNode(t, v)); !errors.Is(e, errBadSchema) {
						t.Fatal("wrong value refusal", e)
					}
					v[field] = original
					if e := c.check(subobjectNode(t, v)); e != nil {
						t.Fatal("valid after", e)
					}
				})
			}
			if field != "runtime" && field != "channel" && field != "visibility" && field != "repository_id" && field != "create_result_digest" {
				v := subobjectCopy(c.valid)
				v[field] = "A" + strings.Repeat("a", 127)
				if e := c.check(subobjectNode(t, v)); e != nil {
					t.Fatal("exact ID128", e)
				}
				v[field] = "A" + strings.Repeat("a", 128)
				if e := c.check(subobjectNode(t, v)); !errors.Is(e, errInputLimit) {
					t.Fatal("ID129", e)
				}
				if e := c.check(subobjectNode(t, c.valid)); e != nil {
					t.Fatal("valid after ID cap", e)
				}
			}
		}
	}
	for _, runtime := range []string{"claude", "codex"} {
		for _, channel := range []string{"encrypted-dm", "encrypted-group"} {
			v, e := parseCycleNode(subobjectNode(t, map[string]any{"cycle_id": "Case_A", "runtime": runtime, "channel": channel}))
			if e != nil || v == nil || v.runtime != runtime || v.channel != channel || v.cycleID != "Case_A" {
				t.Fatal("exact cycle values", v, e)
			}
		}
	}
}

// Decoded scalar values preserve case and exact spellings; caller-buffer
// mutation cannot alter the scanner's retained strings or typed subobjects.
func TestPayloadSubobjectsExactValues(t *testing.T) {
	audience, e := parseAudienceNode(subobjectNode(t, map[string]any{"deployment_id": "D-A", "executor_id": "E:B"}))
	if e != nil || audience.deploymentID != "D-A" || audience.executorID != "E:B" {
		t.Fatal("audience", e)
	}
	use, e := parseUseNode(subobjectNode(t, map[string]any{"cycle_id": "C-A", "operation_use_id": "C-A/create"}))
	if e != nil || use.cycleID != "C-A" || use.operationUseID != "C-A/create" {
		t.Fatal("use", e)
	}
	raw := []byte(`{"name":"Repo_A","organization":"Org.A","visibility":"private"}`)
	n, e := parseCanonical(raw, certificateWire)
	if e != nil {
		t.Fatal(e)
	}
	create, e := parseCreateTargetNode(n)
	if e != nil {
		t.Fatal(e)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if create.visibility != "private" || create.organization != "Org.A" || create.name != "Repo_A" {
		t.Fatal("changed resource bytes")
	}
	grant, e := parseDeleteGrantTargetNode(subobjectNode(t, map[string]any{"organization": "Org.A", "name": "Repo_A", "paired_create_entry": "repo-create"}))
	if e != nil || grant.pairedCreateEntry != "repo-create" || grant.organization != "Org.A" || grant.name != "Repo_A" {
		t.Fatal("delete grant", e)
	}
	request, e := parseDeleteRequestTargetNode(subobjectNode(t, map[string]any{"organization": "Org.A", "name": "Repo_A", "repository_id": "18446744073709551615", "create_operation_use_id": "C-A/create", "create_result_digest": strings.Repeat("a", 64)}))
	if e != nil || request.repositoryID != ^uint64(0) || request.createOperationUseID != "C-A/create" || request.organization != "Org.A" || request.name != "Repo_A" {
		t.Fatal("delete request", e)
	}
	for _, b := range request.createResultDigest {
		if b != 0xaa {
			t.Fatal("changed digest")
		}
	}
}

// Canonical ingress applies the ordinary resource-text byte cap before
// subobject decoding; representation does not certify provider-name validity.
func TestPayloadSubobjectsResourceTextBounds(t *testing.T) {
	for _, c := range subobjectCases(t) {
		for _, field := range []string{"organization", "name"} {
			if _, ok := c.valid[field]; !ok {
				continue
			}
			for _, text := range []string{"", "Case/ Exact.A", strings.Repeat("x", 1024)} {
				v := subobjectCopy(c.valid)
				v[field] = text
				n := subobjectNode(t, v)
				if e := c.check(n); e != nil {
					t.Fatal(c.name, field, "bounded text", e)
				}
			}
			v := subobjectCopy(c.valid)
			v[field] = strings.Repeat("x", 1025)
			raw, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			n, e := parseCanonical(raw, certificateWire)
			if n != nil || !errors.Is(e, errInputLimit) {
				t.Fatal("ordinary text1025", n, e)
			}
			if e := c.check(subobjectNode(t, c.valid)); e != nil {
				t.Fatal("valid after limit", e)
			}
		}
		if c.name == "delete-request" {
			v := subobjectCopy(c.valid)
			v["repository_id"] = "1"
			got, e := parseDeleteRequestTargetNode(subobjectNode(t, v))
			if e != nil || got == nil || got.repositoryID != 1 {
				t.Fatal("decimal minimum", e)
			}
		}
	}
}
