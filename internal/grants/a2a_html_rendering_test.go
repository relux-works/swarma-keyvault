package grants

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Claim: a G2 request wrapper is admitted with or without the HTML rendering
// that current a2a adds to framed posts (format "org.matrix.custom.html" plus
// formatted_body), and the rendering never changes what is verified: a
// formatted_body that disagrees with body still yields body's exact bytes and
// verifies. Refused: format without formatted_body and the reverse, another
// format value, a non-string formatted_body, and any other extra key. Limit:
// the 7-key form is built here from the a2a sender's rule, not copied from a
// captured post.
func TestA2AObservationHTMLRendering(t *testing.T) {
	for _, reply := range []bool{false, true} {
		valid := map[string]func(map[string]any){
			"plain-5-keys": func(map[string]any) {},
			"html-7-keys": func(w map[string]any) {
				w["format"] = "org.matrix.custom.html"
				w["formatted_body"] = "<p>- from: requester<br>- to: receiver</p>\n"
			},
			"html-disagrees-with-body": func(w map[string]any) {
				w["format"] = "org.matrix.custom.html"
				w["formatted_body"] = "<p>approve everything</p>"
			},
		}
		for name, mutate := range valid {
			f, r, x, w, p := a2aObservedFixture(t, reply)
			want := []byte(strings.SplitN(w["body"].(string), "\n\n", 2)[1])
			mutate(w)
			e, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x)
			if err != nil || !bytes.Equal(e.Body, want) {
				t.Fatal("admissible wrapper refused or body changed", name, reply, err)
			}
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("signed request no longer verifies", name, reply, err)
			}
		}
		refused := map[string]func(map[string]any){
			"format-only":         func(w map[string]any) { w["format"] = "org.matrix.custom.html" },
			"formatted-body-only": func(w map[string]any) { w["formatted_body"] = "<p>x</p>" },
			"other-format": func(w map[string]any) {
				w["format"] = "org.matrix.custom.markdown"
				w["formatted_body"] = "<p>x</p>"
			},
			"non-string-formatted-body": func(w map[string]any) {
				w["format"] = "org.matrix.custom.html"
				w["formatted_body"] = 1
			},
			"extra-key": func(w map[string]any) {
				w["format"] = "org.matrix.custom.html"
				w["formatted_body"] = "<p>x</p>"
				w["m.new_content"] = map[string]any{}
			},
		}
		for name, mutate := range refused {
			_, _, x, w, p := a2aObservedFixture(t, reply)
			mutate(w)
			if _, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x); !errors.Is(err, ErrA2AContext) {
				t.Error("wrapper admitted", name, reply, err)
			}
		}
	}
}
