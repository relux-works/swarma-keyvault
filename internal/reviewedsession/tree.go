package reviewedsession

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// safeTree discloses every syntactically admitted field/array slot in a
// deterministic, reversible representation. It is a renderer component only,
// not a substitute for a complete profile projection/completeness validator.
// In particular, an unknown or missing signed field requires the real profile
// validator to refuse before this function is used in a future frozen review.
func safeTree(raw []byte) (string, error) {
	m, err := strictObject(raw, snapshotMax)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := treeValue(&b, "$", m); err != nil {
		return "", err
	}
	return b.String(), nil
}

func treeValue(b *strings.Builder, path string, value any) error {
	// Every emitted line is bounded before it is appended. Paths are quoted
	// safe field names and renderer-owned one-based array indices.
	line := func(s string) error {
		if len(path)+2+len(s)+1 > reviewMax-b.Len() {
			return errDisplay
		}
		b.WriteString(path)
		b.WriteString(": ")
		b.WriteString(s)
		b.WriteByte('\n')
		return nil
	}
	switch v := value.(type) {
	case map[string]any:
		if err := line("object(" + strconv.Itoa(len(v)) + ")"); err != nil {
			return err
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key, err := safeString(k)
			if err != nil {
				return err
			}
			if err := treeValue(b, path+"["+key+"]", v[k]); err != nil {
				return err
			}
		}
	case []any:
		if err := line("array(" + strconv.Itoa(len(v)) + ")"); err != nil {
			return err
		}
		for i, item := range v {
			if err := treeValue(b, path+"["+strconv.Itoa(i+1)+"]", item); err != nil {
				return err
			}
		}
	case string:
		q, err := safeString(v)
		if err != nil {
			return err
		}
		return line(q)
	case json.Number:
		return line(string(v))
	case bool:
		return line(strconv.FormatBool(v))
	case nil:
		return line("null")
	default:
		return errSchema
	}
	return nil
}
