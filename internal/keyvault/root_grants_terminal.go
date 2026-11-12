package keyvault

import (
	"bytes"
	"context"
	"strconv"
)

// Physical Return normalization belongs ONLY to the self-opened controlling
// tty transport. Direct grammar callers still must supply LF/CRLF. This finite
// state retains no word bytes: CR ends one line; one following LF is consumed;
// CR CR ends two lines and therefore exposes an empty line to strict grammar.
type rootGrantsTTYMapper struct{ afterCR bool }

func (m *rootGrantsTTYMapper) mapByte(b byte) (byte, bool) {
	if m.afterCR {
		m.afterCR = false
		if b == '\n' {
			return 0, false
		}
	}
	if b == '\r' {
		m.afterCR = true
		return '\n', true
	}
	return b, true
}

// Private pure line-I/O grammar seam. Each line is an OWNED bounded byte buffer
// including LF or CRLF, cleared by the consumer. Production has one source:
// readRootGrantsTTY opens /dev/tty itself. No exported alternative input exists.
type rootGrantsLineIO interface {
	readLine(context.Context, int) ([]byte, error)
	prompt(context.Context, []byte) error
}

func rootGrantsLineBody(line []byte) ([]byte, bool) {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return nil, false
	}
	body := line[:len(line)-1]
	if len(body) > 0 && body[len(body)-1] == '\r' {
		body = body[:len(body)-1]
	}
	return body, true
}

func rootGrantsEnglishWord(word []byte) bool {
	if len(word) == 0 || len(word) > 8 {
		return false
	}
	for _, b := range word {
		if b < 'a' || b > 'z' {
			return false
		}
	}
	for _, known := range recoveryWords {
		if bytes.Equal(word, []byte(known)) {
			return true
		}
	}
	return false
}

func readRootGrantsNumbered(ctx context.Context, terminal rootGrantsLineIO) ([]byte, error) {
	ctx = rootGrantsBudgetView(ctx)
	if err := rootGrantsContextError(ctx); err != nil {
		return nil, err
	}
	if terminal == nil {
		return nil, recoveryRefuse("terminal_required")
	}
	ctx, cancel, budgetError := rootGrantsInputBudget(ctx)
	if budgetError != nil {
		return nil, budgetError
	}
	defer cancel()
	phrase := make([]byte, 0, 512)
	returned := false
	defer func() {
		if !returned {
			clear(phrase[:cap(phrase)])
		}
	}()
	if terminal.prompt(ctx, []byte("Enter exactly 24 numbered English words, one line at a time. Input hidden. Existing Nostr and Namecoin pins must both match before any wrapping or storage.\n")) != nil {
		return nil, rootGrantsInputError(ctx)
	}
	for ordinal := 1; ordinal <= 24; ordinal++ {
		if err := rootGrantsContextError(ctx); err != nil {
			return nil, err
		}
		number := strconv.Itoa(ordinal) // public ordinal only, never word data
		if terminal.prompt(ctx, []byte("Line "+number+" of 24 (type \""+number+". word\", hidden): ")) != nil {
			return nil, rootGrantsInputError(ctx)
		}
		line, err := terminal.readLine(ctx, 32)
		if err != nil {
			clear(line)
			return nil, rootGrantsInputError(ctx)
		}
		body, complete := rootGrantsLineBody(line)
		prefix := []byte(number + ". ")
		code := ""
		switch {
		case !complete || len(line) > 32:
			code = "invalid_word_count"
		case bytes.Equal(body, []byte("END")):
			code = "invalid_word_count"
		case !bytes.HasPrefix(body, prefix):
			code = "invalid_word_number"
		case !rootGrantsEnglishWord(body[len(prefix):]):
			code = "invalid_mnemonic"
		default:
			if ordinal != 1 {
				phrase = append(phrase, ' ')
			}
			phrase = append(phrase, body[len(prefix):]...)
		}
		clear(line)
		if code != "" {
			return nil, recoveryRefuse(code)
		}
	}
	if terminal.prompt(ctx, []byte("Type END to finish numbered input: ")) != nil {
		return nil, rootGrantsInputError(ctx)
	}
	line, err := terminal.readLine(ctx, 32)
	body, complete := rootGrantsLineBody(line)
	end := err == nil && len(line) <= 32 && complete && bytes.Equal(body, []byte("END"))
	clear(line)
	if !end {
		if err != nil {
			return nil, rootGrantsInputError(ctx)
		}
		return nil, recoveryRefuse("invalid_word_count")
	}
	indices, err := parseMnemonic(phrase)
	clear(indices)
	if err != nil {
		return nil, err
	}
	if err := rootGrantsContextError(ctx); err != nil {
		return nil, err
	}
	returned = true
	return phrase, nil // private owned bytes, consumed immediately by preparation
}

func rootGrantsInputError(ctx context.Context) error {
	if err := rootGrantsContextError(ctx); err != nil {
		return err
	}
	return recoveryRefuse("input_canceled")
}
