// Command agentnostrfixture freezes public test-only Nostr custody fixtures.
// It has no production-key or native-store input route.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--write" {
		fmt.Fprintln(os.Stderr, "usage: agentnostrfixture --write")
		os.Exit(2)
	}
	root, err := findRepositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentnostrfixture: repository root unavailable")
		os.Exit(1)
	}
	files, err := generateFiles(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentnostrfixture: fixture generation refused")
		os.Exit(1)
	}
	if err := writeFiles(filepath.Join(root, fixtureDirectory), files); err != nil {
		fmt.Fprintln(os.Stderr, "agentnostrfixture: fixture write failed")
		os.Exit(1)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr, "wrote %d public fixture files\n", len(names))
}
