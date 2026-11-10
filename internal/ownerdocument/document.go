// Package ownerdocument prepares exact UTF-8 files for an attended owner
// signature. It uses the existing mac-keyvault file-signing contract, not a
// grant/envelope codec. Native review requires the source-matched macOS helper.
package ownerdocument

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

const (
	MaxDocumentBytes = 16 * 1024
	MaxLines         = 256
	MaxLineScalars   = 160
	MaxSPKIBytes     = 1024
)

var (
	ErrInput             = errors.New("owner-document-input: require a nonempty regular UTF-8 file of at most 16384 bytes, 256 lines and 160 scalars per line")
	ErrDisplay           = errors.New("owner-document-display: unsupported or ambiguous character/spacing; document was not normalized")
	ErrPublic            = errors.New("owner-document-public-key: require exact P-256 SPKI DER")
	ErrChanged           = errors.New("owner-document-changed: source bytes differ from the reviewed document")
	ErrConfirmation      = errors.New("owner-document-not-confirmed: complete unchanged text must be confirmed")
	ErrNativeUnavailable = errors.New("owner-document-native-unavailable: full-document AppKit/Secure Enclave review requires macOS and its matching native helper")
	ErrSignature         = errors.New("owner-document-signature-invalid: exact document did not verify with strict low-S DER under the independent public pin")
	ErrOutcomeUnknown    = errors.New("owner-document-outcome-unknown: private dispatch may have occurred; no signature released; do not retry")
)

// Prepared owns its document and independent public pin. No JSON conversion,
// newline insertion, Unicode normalization, domain prefix or envelope is signed.
type Prepared struct {
	address  keyvault.Address
	document []byte
	public   []byte
	digest   [32]byte
}

func Prepare(address keyvault.Address, document, publicDER []byte) (*Prepared, error) {
	if err := ownerkey.ValidateAddress(address); err != nil {
		return nil, err
	}
	if err := admitText(document); err != nil {
		return nil, err
	}
	// ParseSPKI also accepts PEM; this route deliberately requires unchanged DER.
	der, public, err := keyvault.ParseSPKI(publicDER)
	if err != nil || public == nil || public.Curve != elliptic.P256() || len(publicDER) > MaxSPKIBytes || !bytes.Equal(der, publicDER) {
		return nil, ErrPublic
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonical, publicDER) {
		return nil, ErrPublic
	}
	return &Prepared{address: address, document: bytes.Clone(document), public: bytes.Clone(publicDER), digest: sha256.Sum256(document)}, nil
}

// Admission is deliberately narrower than all valid UTF-8: printable ASCII,
// Russian letters and the explicit punctuation below, plus ASCII space/LF.
// Other scripts/symbols, controls, bidi/zero-width, combining marks, non-ASCII
// whitespace and repeated/edge spaces refuse. Blank lines are preserved.
// This is a conservative display policy, not a claim about native font layout.
func admitText(document []byte) error {
	if len(document) == 0 || len(document) > MaxDocumentBytes || !utf8.Valid(document) {
		return ErrInput
	}
	// A document cannot impersonate the plain-text renderer's boundaries.
	for _, marker := range []string{"BEGIN DOCUMENT", "END DOCUMENT", "UNSIGNED exact UTF-8 document;"} {
		if bytes.Contains(document, []byte(marker)) {
			return ErrDisplay
		}
	}
	lines, column, previousSpace, visible := 1, 0, false, false
	for _, r := range string(document) {
		if r == '\n' {
			if previousSpace {
				return ErrDisplay
			}
			lines++
			if lines > MaxLines {
				return ErrInput
			}
			column, previousSpace = 0, false
			continue
		}
		if r == ' ' {
			if column == 0 || previousSpace {
				return ErrDisplay
			}
		} else if !displayRune(r) {
			return ErrDisplay
		} else {
			visible = true
		}
		column++
		if column > MaxLineScalars {
			return ErrInput
		}
		previousSpace = r == ' '
	}
	if previousSpace || !visible {
		return ErrDisplay
	}
	return nil
}

func displayRune(r rune) bool {
	if r >= '!' && r <= '~' || r >= 'А' && r <= 'я' || r == 'Ё' || r == 'ё' {
		return true
	}
	switch r {
	case '«', '»', '–', '—', '‘', '’', '“', '”', '…', '№':
		return true
	}
	return false
}

// ReadFile bounds bytes before parsing; special files and symlinks refuse.
// Descriptor rechecks detect common replacements, not a hostile same-UID race.
func ReadFile(path string, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > MaxDocumentBytes {
		return nil, ErrInput
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrInput
	}
	file, err := openRegular(path)
	if err != nil {
		return nil, ErrInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, ErrInput
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || len(raw) > int(maximum) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, ErrInput
	}
	return raw, nil
}

func (p *Prepared) CheckSource(current []byte) error {
	if p == nil || !bytes.Equal(p.document, current) {
		return ErrChanged
	}
	return nil
}

func (p *Prepared) Digest() [32]byte { return p.digest }

// Render writes ALL admitted bytes, including an existing terminal LF. Framing
// explicitly reports the byte count and LF state; its separator is not document
// data. This writer operation alone supplies neither visibility nor consent.
func (p *Prepared) Render(w io.Writer) error {
	if p == nil || len(p.document) == 0 || w == nil {
		return ErrInput
	}
	lf := "absent"
	if p.document[len(p.document)-1] == '\n' {
		lf = "present"
	}
	header := fmt.Sprintf("UNSIGNED exact UTF-8 document; %d bytes; terminal LF %s\nKey: %s\nSHA256: %x\nBEGIN DOCUMENT (next %d bytes)\n", len(p.document), lf, p.address, p.digest, len(p.document))
	for _, part := range [][]byte{[]byte(header), bytes.Clone(p.document), []byte("\nEND DOCUMENT (separator LF above is not document data)\n")} {
		if n, err := w.Write(part); err != nil {
			return err
		} else if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Prompt is only the brief presence reason. The complete rendering and explicit
// confirmation must precede it. Including the actual Enclave prefix/key suffix
// stays below d154's 200-scalar bound, without helper filtering or truncation.
func (p *Prepared) Prompt(digest []byte) string {
	if p == nil || len(p.document) == 0 || !bytes.Equal(digest, p.digest[:]) {
		return ""
	}
	return "sign exact UTF-8 document SHA256 " + hex.EncodeToString(p.digest[:])
}

func (p *Prepared) Verify(signatureDER []byte) error {
	if p == nil || len(p.document) == 0 {
		return ErrInput
	}
	sig, err := keyvault.ParseSignature(signatureDER, keyvault.FormatSignatureDERLowS)
	if err != nil || !sig.IsLowS() {
		return ErrSignature
	}
	ok, err := keyvault.VerifyDigest(p.public, p.digest[:], sig)
	if err != nil || !ok {
		return ErrSignature
	}
	return nil
}

// SignFile uses the typed full-document native route, never generic digest-only
// signing. Linux cannot construct custody or claim native visibility/consent.
func (p *Prepared) SignFile(ctx context.Context, path string) ([]byte, error) {
	if p == nil || len(p.document) == 0 || ctx == nil {
		return nil, ErrInput
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := ReadFile(path, MaxDocumentBytes)
		if err != nil {
			return err
		}
		if err := p.CheckSource(raw); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := check(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "darwin" {
		return nil, ErrNativeUnavailable
	}
	store := keyvault.DefaultEnclaveStore()
	if helper, ok := store.Helper.(keyvault.ExecEnclaveHelper); ok {
		helper.InteractiveTimeout = 5 * time.Minute
		store.Helper = helper
	}
	manager := keyvault.NewOwnerDocumentManager(store)
	return p.signNative(ctx, manager, check)
}

func (p *Prepared) signNative(ctx context.Context, manager *keyvault.Manager, check func() error) ([]byte, error) {
	if p == nil || manager == nil || check == nil || ctx == nil {
		return nil, ErrInput
	}
	if err := check(); err != nil {
		return nil, err
	}
	// Conservatively classify every error after backend admission as potentially
	// dispatched. No timeout/cancellation or output failure is safe to auto-retry.
	admitted := false
	digest := p.digest
	result, err := manager.SignOwnerDocument(ctx, p.address, digest[:], bytes.Clone(p.document), func(key keyvault.ResolvedSigningKey) error {
		if key.Address != p.address || key.Store != keyvault.StoreEnclave || !key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, p.public) {
			return ErrPublic
		}
		if err := check(); err != nil {
			return err
		}
		admitted = true
		return nil
	}, check)
	if err != nil {
		if admitted {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		return nil, err
	}
	if err := check(); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	der, err := result.Signature.Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := p.Verify(der); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return der, nil
}
