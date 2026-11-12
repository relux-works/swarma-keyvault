package keyvault

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
)

type rootGrantsLines28 struct {
	lines        [][]byte
	returned     [][]byte
	prompts      [][]byte
	reads        int
	failAt       int
	failPromptAt int
	cancelAt     int
	cancel       context.CancelFunc
}

func (f *rootGrantsLines28) prompt(_ context.Context, public []byte) error {
	f.prompts = append(f.prompts, bytes.Clone(public))
	if f.failPromptAt == len(f.prompts) {
		return errors.New("SYNTHETIC_DIAGNOSTIC_28")
	}
	return nil
}
func (f *rootGrantsLines28) readLine(_ context.Context, _ int) ([]byte, error) {
	f.reads++
	if f.cancelAt == f.reads && f.cancel != nil {
		f.cancel()
	}
	if f.failAt == f.reads || f.reads > len(f.lines) {
		return nil, errors.New("SYNTHETIC_DIAGNOSTIC_28")
	}
	line := bytes.Clone(f.lines[f.reads-1])
	f.returned = append(f.returned, line)
	return line, nil
}

func rootGrantsNumbered28(phrase, ending []byte) [][]byte {
	words := bytes.Fields(phrase) // published test phrase only
	var lines [][]byte
	for i, word := range words {
		line := append([]byte(strconv.Itoa(i+1)+". "), word...)
		line = append(line, ending...)
		lines = append(lines, line)
	}
	return append(lines, append([]byte("END"), ending...))
}

func rootGrantsReturnedCleared28(t *testing.T, f *rootGrantsLines28) {
	t.Helper()
	for _, line := range f.returned {
		for _, b := range line {
			if b != 0 {
				t.Fatal("owned numbered line survived consumption/refusal")
			}
		}
	}
	public := bytes.Join(f.prompts, nil)
	for _, word := range bytes.Fields([]byte(recoveryFixturePhrase)) {
		if bytes.Contains(public, word) {
			t.Fatal("word data appeared in public numbered prompts")
		}
	}
}

// Claim: exact LF/CRLF numbered published24-word phrase plus END is accepted
// once; only26 public prompts appear and every input line allocation is cleared.
// Limits: pure line I/O, not actual /dev/tty, physical Return, echo or termios.
func TestRootGrantsTerminal28Numbered(t *testing.T) {
	for _, ending := range [][]byte{{'\n'}, {'\r', '\n'}} {
		f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), ending)}
		phrase, err := readRootGrantsNumbered(context.Background(), f)
		if err != nil || !bytes.Equal(phrase, []byte(recoveryFixturePhrase)) || f.reads != 25 || len(f.prompts) != 26 {
			t.Fatal("valid exact numbered input refused")
		}
		clear(phrase)
		rootGrantsReturnedCleared28(t, f)
	}
}

func rootGrantsBadLines28() map[string][][]byte {
	bad := make(map[string][][]byte)
	first := map[string][]byte{
		"blank": []byte("\n"), "leading-zero": []byte("01. what\n"), "skipped": []byte("2. what\n"),
		"missing-dot": []byte("1 what\n"), "space-before": []byte(" 1. what\n"), "double-space": []byte("1.  what\n"),
		"trailing-space": []byte("1. what \n"), "uppercase": []byte("1. WHAT\n"), "non-ascii": []byte("1. wh\xc3\xa4t\n"),
		"unknown-word": []byte("1. zzzzzzzz\n"), "embedded-nul": []byte("1. wh\x00at\n"), "oversize": bytes.Repeat([]byte{'x'}, 33),
		"single-line-phrase": append([]byte(recoveryFixturePhrase), '\n'), "early-END": []byte("END\n"),
		"bare-CR-grammar": []byte("1. what\r"), "no-newline": []byte("1. what"),
	}
	for name, line := range first {
		lines := rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})
		lines[0] = line
		bad[name] = lines
	}
	for _, name := range []string{"duplicate", "reordered", "23-words", "25-words", "wrong-END", "extra-END-space", "no-END", "bad-checksum"} {
		lines := rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})
		switch name {
		case "duplicate":
			lines[1] = []byte("1. bleak\n")
		case "reordered":
			lines[0], lines[1] = lines[1], lines[0]
		case "23-words":
			lines = append(lines[:23], []byte("END\n"))
		case "25-words":
			lines[24] = []byte("25. abandon\n")
		case "wrong-END":
			lines[24] = []byte("end\n")
		case "extra-END-space":
			lines[24] = []byte("END \n")
		case "no-END":
			lines = lines[:24]
		case "bad-checksum":
			phrase := bytes.TrimSuffix(bytes.Repeat([]byte("abandon "), 24), []byte{' '})
			lines = rootGrantsNumbered28(phrase, []byte{'\n'})
			clear(phrase)
		}
		bad[name] = lines
	}
	return bad
}

// Claim: every grammar/count/checksum refusal returns no phrase, never rereads
// a bad line, clears owned input and never copies words into public prompts.
// Limits: pure parser; pin/no-wrap composition is checked in engine tests.
func TestRootGrantsTerminal28Refusals(t *testing.T) {
	for name, lines := range rootGrantsBadLines28() {
		t.Run(name, func(t *testing.T) {
			f := &rootGrantsLines28{lines: lines}
			phrase, err := readRootGrantsNumbered(context.Background(), f)
			if err == nil || phrase != nil || f.reads > 25 {
				t.Fatal("invalid numbered input accepted or reread")
			}
			rootGrantsReturnedCleared28(t, f)
		})
	}
	for _, at := range []int{1, 12, 25} {
		ctx, cancel := context.WithCancel(context.Background())
		f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'}), cancelAt: at, cancel: cancel}
		phrase, err := readRootGrantsNumbered(ctx, f)
		cancel()
		if err == nil || phrase != nil || f.reads != at {
			t.Fatal("canceled numbered input continued or returned a phrase")
		}
		rootGrantsReturnedCleared28(t, f)
	}
	for _, at := range []int{1, 2, 14, 26} {
		f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'}), failPromptAt: at}
		phrase, err := readRootGrantsNumbered(context.Background(), f)
		if err == nil || phrase != nil {
			t.Fatal("prompt failure returned word material")
		}
		rootGrantsReturnedCleared28(t, f)
	}
	for _, at := range []int{1, 12, 25} {
		f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'}), failAt: at}
		phrase, err := readRootGrantsNumbered(context.Background(), f)
		if err == nil || phrase != nil || f.reads != at {
			t.Fatal("EOF/read failure was retried or returned words")
		}
		rootGrantsReturnedCleared28(t, f)
	}
}

func rootGrantsMapLines28(raw []byte) [][]byte {
	var mapper rootGrantsTTYMapper
	var lines [][]byte
	line := make([]byte, 0, 32)
	for _, b := range raw {
		mapped, emit := mapper.mapByte(b)
		if !emit {
			continue
		}
		line = append(line, mapped)
		if mapped == '\n' {
			lines = append(lines, line)
			line = make([]byte, 0, 32)
		}
	}
	if len(line) != 0 {
		lines = append(lines, line)
	}
	return lines
}

// Claim: ONLY physical tty transport maps CR/LF/CRLF to one line, CR CR and
// CRLF LF expose a blank/refusal, and CR inside a word cannot yield an accepted
// phrase. Direct parser bare CR remains refused by the paired grammar control.
// Limits: pure finite mapper, not actual tty/PTY/echo/restoration qualification.
func TestRootGrantsTerminal28Transport(t *testing.T) {
	for _, ending := range [][]byte{{'\n'}, {'\r', '\n'}, {'\r'}} {
		raw := bytes.Join(rootGrantsNumbered28([]byte(recoveryFixturePhrase), ending), nil)
		lines := rootGrantsMapLines28(raw)
		if len(lines) != 25 {
			t.Fatal("transport counted a terminator twice")
		}
		f := &rootGrantsLines28{lines: lines}
		phrase, err := readRootGrantsNumbered(context.Background(), f)
		if err != nil || !bytes.Equal(phrase, []byte(recoveryFixturePhrase)) {
			t.Fatal("valid physical Return transport refused")
		}
		clear(phrase)
		rootGrantsReturnedCleared28(t, f)
	}
	for _, raw := range [][]byte{[]byte("1. what\r\r2. bleak\n"), []byte("1. what\r\n\n2. bleak\n"), []byte("1. wh\rat\n")} {
		f := &rootGrantsLines28{lines: rootGrantsMapLines28(raw)}
		phrase, err := readRootGrantsNumbered(context.Background(), f)
		if err == nil || phrase != nil {
			t.Fatal("empty line/inside-word CR admitted a phrase")
		}
		rootGrantsReturnedCleared28(t, f)
	}
}
