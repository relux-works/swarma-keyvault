package signerclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
)

// Options configure Start.
type Options struct {
	// Binary is the mac-keyvault executable; empty resolves "mac-keyvault"
	// on PATH.
	Binary string
	// Address is <service>/<purpose>; the server refuses anything else
	// (raw labels included) before it touches the keychain.
	Address string
	// Kind is the record kind; empty means key.
	Kind string
	// Version pins one generation; 0 binds the newest generation at the
	// hello, and that generation stays bound for the whole session.
	Version int
	// Stderr receives the server's stderr; nil discards it.
	Stderr io.Writer
}

// Errors the client itself raises. A refused or failed operation is a
// *Error carrying the server's code.
var (
	// ErrContract: the hello announced a contract this package does not
	// speak (or none at all); the server was stopped.
	ErrContract = errors.New("signerclient: unsupported contract")
	// ErrProtocol: the server wrote something that is not a contract-1
	// response to the pending request (unparsable line, foreign id, EOF,
	// an envelope that is neither {ok:true,result} nor {ok:false,error}
	// with a declared stream code, a hello bound to another identity
	// than the one requested); the server is killed and the client is
	// unusable afterwards.
	ErrProtocol = errors.New("signerclient: protocol violation")
	// ErrClosed: Close was called or a protocol violation ended the session.
	ErrClosed = errors.New("signerclient: session closed")
)

// Client is one `mac-keyvault signer serve` process. Calls are serialised;
// a Client is safe for concurrent use.
type Client struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines *bufio.Reader
	hello Hello
	// pub is the public key the hello fingerprint attests, fetched
	// through the pub gate once and used to verify every signature and
	// verdict the server returns.
	pub    *ecdsa.PublicKey
	mu     sync.Mutex
	nextID uint64
	broken error
	waited bool
	waitE  error
}

// Start spawns the server, reads the hello line and refuses any contract
// other than Contract (ErrContract) and any hello that is not the binding
// requested — see Hello (ErrProtocol). ctx bounds the process: when it is
// done the server is killed. A startup failure (address does not resolve,
// foreign label, usage) is returned as *Error after the process exited;
// a startup error whose code is not a stream code is ErrProtocol.
func Start(ctx context.Context, opts Options) (*Client, error) {
	binary := opts.Binary
	if binary == "" {
		binary = "mac-keyvault"
	}
	if opts.Address == "" {
		return nil, fmt.Errorf("signerclient: Address is required")
	}
	args := []string{"signer", "serve", "--address", opts.Address}
	if opts.Kind != "" {
		args = append(args, "--kind", opts.Kind)
	}
	if opts.Version != 0 {
		args = append(args, "--version", strconv.Itoa(opts.Version))
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stderr = opts.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{cmd: cmd, stdin: stdin, lines: bufio.NewReader(stdout)}
	resp, err := c.readResponse(ctx, true)
	if err != nil {
		c.abort()
		return nil, fmt.Errorf("%w: no hello line: %v", ErrProtocol, err)
	}
	if resp.Contract != Contract {
		c.abort()
		return nil, fmt.Errorf("%w: server announced contract %d, this client speaks %d", ErrContract, resp.Contract, Contract)
	}
	// The envelope is judged as a whole before ok is trusted: a hello may
	// not carry a result next to an error, whatever ok says.
	if err := checkEnvelope(resp, false); err != nil {
		c.abort()
		return nil, fmt.Errorf("%w: hello: %v", ErrProtocol, err)
	}
	if !resp.OK {
		_ = c.abort()
		return nil, resp.Error
	}
	// The hello result is read like every result: members present,
	// non-null, typed, none repeated, none undefined.
	c.hello, err = decodeHelloResult(resp.Result)
	if err != nil {
		c.abort()
		return nil, fmt.Errorf("%w: hello result: %v", ErrProtocol, err)
	}
	if err := checkHello(c.hello, opts); err != nil {
		c.abort()
		return nil, fmt.Errorf("%w: hello: %v", ErrProtocol, err)
	}
	return c, nil
}

// checkHello judges the hello as one binding between the signer identity
// the consumer requested and the one the server announces. Every member
// is checked; the first mismatch names itself. A hello that passes attests
// every later signature: the tool is mac-keyvault, the address and kind
// are the ones asked for, the generation is pinned (never 0) and, when one
// was requested, that one, the label and fingerprint are present, and the
// operation set is exactly contract 1's.
func checkHello(h Hello, opts Options) error {
	if h.Tool != Tool {
		return fmt.Errorf("tool %q, want %q", h.Tool, Tool)
	}
	if h.Address != opts.Address {
		return fmt.Errorf("address %q, requested %q", h.Address, opts.Address)
	}
	kind := opts.Kind
	if kind == "" {
		kind = KindKey
	}
	if h.Kind != kind {
		return fmt.Errorf("kind %q, requested %q", h.Kind, kind)
	}
	// The hello attests one generation for the whole stream; a server that
	// announces none (version 0) or another than the one requested cannot
	// be trusted to sign with the key the consumer configured.
	if h.Version < 1 {
		return fmt.Errorf("does not pin a generation (version %d)", h.Version)
	}
	if opts.Version != 0 && h.Version != opts.Version {
		return fmt.Errorf("requested version %d, hello bound version %d", opts.Version, h.Version)
	}
	if h.Label == "" {
		return errors.New("label is missing")
	}
	if h.Fingerprint == "" {
		return errors.New("fingerprint is missing")
	}
	if len(h.Ops) != len(Ops) {
		return fmt.Errorf("ops %q, want %q", h.Ops, Ops)
	}
	for i, op := range Ops {
		if h.Ops[i] != op {
			return fmt.Errorf("ops %q, want %q", h.Ops, Ops)
		}
	}
	return nil
}

// checkEnvelope judges the shape of one response — hello or reply — as a
// whole, before anything branches on ok. Exactly two shapes are contract
// 1: ok true with a result and no error member, and ok false with an
// error whose code is one of the codes a contract-1 stream may carry (the
// Stream rows of ErrorContract) and, only where the op documents a
// partial result next to its refusal (verify's verdict), a result. Every
// other combination — ok true with an error, ok true without a result, ok
// false without an error, ok false with a result where none is documented,
// an undeclared, empty or self-minted code on either side of ok — is a
// contract break, not a refusal a consumer could act on. Judging the
// error member only when ok is false would let a server keep a foreign
// code and flip ok to true past the gate. resp comes from decodeEnvelope,
// so its members are faithful to the line: Error is nil exactly when the
// error member was absent (a null error was refused there) and Result is
// empty exactly when the result member was absent (a null result too).
func checkEnvelope(resp Response, resultOnError bool) error {
	hasResult := len(resp.Result) != 0
	if resp.Error != nil {
		if !IsStreamCode(resp.Error.Code) {
			return fmt.Errorf("error code %q is not a contract-1 stream code", resp.Error.Code)
		}
		if resp.OK {
			return fmt.Errorf("response is ok and carries error %q", resp.Error.Code)
		}
		if hasResult && !resultOnError {
			return fmt.Errorf("response is not ok (%s) and carries a result the op does not document", resp.Error.Code)
		}
		return nil
	}
	if !resp.OK {
		return errors.New("response is not ok and carries no error")
	}
	if !hasResult {
		return errors.New("response is ok and carries no result")
	}
	return nil
}

// Hello is what the server bound to: label, fingerprint, ops.
func (c *Client) Hello() Hello { return c.hello }

// Call sends one request and returns its response. The id is assigned
// here; a response with another id is ErrProtocol. The envelope is judged
// as a whole (checkEnvelope) before ok is read, and then the RESULT is
// judged (checkResult) against the pending request and the accepted
// hello before it is returned: a response with ok false and a declared
// stream code is returned together with its *Error so a caller can read
// a partial result (verify's verdict) and the session stays usable; any
// other shape — ok true next to an error member, ok true without a
// result, ok false with no error, a result next to a refusal that does
// not document one, a code outside StreamErrorCodes on either side of
// ok, a result with a member missing, null, repeated or undefined, or a
// result that is not bound to this request and this hello (another
// label or fingerprint, another digest, hash or format, a signature the
// attested key did not make, a verdict it does not give) — is
// ErrProtocol, the server is killed and every later call fails. A sign
// or verify request first fetches the attested public key (one pub
// request per session) so the signature or verdict can be checked under
// it.
func (c *Client) Call(ctx context.Context, req Request) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return Response{}, c.broken
	}
	if (req.Op == OpSign || req.Op == OpVerify) && c.pub == nil {
		if _, err := c.call(ctx, Request{Op: OpPub, Format: FormatSPKIDER}); err != nil {
			return Response{}, err
		}
	}
	return c.call(ctx, req)
}

// call is Call under the lock: one request, one response, every gate.
func (c *Client) call(ctx context.Context, req Request) (Response, error) {
	if c.broken != nil {
		return Response{}, c.broken
	}
	c.nextID++
	req.ID = json.RawMessage(strconv.FormatUint(c.nextID, 10))
	line, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		c.broken = fmt.Errorf("%w: write: %v", ErrProtocol, err)
		return Response{}, c.broken
	}
	resp, err := c.readResponse(ctx, false)
	if err != nil {
		return Response{}, c.fail(fmt.Errorf("%w: %w", ErrProtocol, err))
	}
	if !bytes.Equal(bytes.TrimSpace(resp.ID), req.ID) {
		return Response{}, c.fail(fmt.Errorf("%w: response id %s does not answer request %s", ErrProtocol, resp.ID, req.ID))
	}
	if err := checkEnvelope(resp, req.Op == OpVerify); err != nil {
		return Response{}, c.fail(fmt.Errorf("%w: %v", ErrProtocol, err))
	}
	if err := checkResult(req, resp, c.hello, c.pub); err != nil {
		return Response{}, c.fail(fmt.Errorf("%w: %v", ErrProtocol, err))
	}
	if req.Op == OpPub && resp.OK && c.pub == nil {
		// checkResult admitted the SPKI as the one the hello attests.
		c.pub = attestedKey(resp.Result)
	}
	if !resp.OK {
		return resp, resp.Error
	}
	return resp, nil
}

// fail records a protocol violation, kills and reaps the server, and
// returns the error every later call gets.
func (c *Client) fail(err error) error {
	c.broken = err
	c.abort()
	return err
}

// attestedKey reads the public key out of a pub result checkResult has
// admitted (der_base64 or pem); the parse cannot fail after that gate.
func attestedKey(result json.RawMessage) *ecdsa.PublicKey {
	var pub PublicKey
	_ = json.Unmarshal(result, &pub)
	var der []byte
	if pub.PEM != "" {
		block, _ := pem.Decode([]byte(pub.PEM))
		der = block.Bytes
	} else {
		der, _ = base64.StdEncoding.DecodeString(pub.DERBase64)
	}
	key, _ := ParseSPKI(der)
	return key
}

// readResponse reads one line and passes it through decodeEnvelope (the
// raw member-presence gate; hello selects the hello member set) before
// a typed Response exists; ctx cancellation kills the server so the
// blocked read returns.
func (c *Client) readResponse(ctx context.Context, hello bool) (Response, error) {
	type read struct {
		line []byte
		err  error
	}
	done := make(chan read, 1)
	go func() {
		line, err := c.lines.ReadBytes('\n')
		done <- read{line, err}
	}()
	var r read
	select {
	case r = <-done:
	case <-ctx.Done():
		c.abort()
		<-done
		return Response{}, ctx.Err()
	}
	if r.err != nil {
		switch {
		case !errors.Is(r.err, io.EOF):
			return Response{}, r.err
		case len(bytes.TrimSpace(r.line)) == 0:
			return Response{}, fmt.Errorf("server closed the stream (%v)", c.exitStatus())
		}
		// A final line without a newline is still one response.
	}
	resp, err := decodeEnvelope(r.line, hello)
	if err != nil {
		return Response{}, fmt.Errorf("%v: %q", err, bytes.TrimSpace(r.line))
	}
	return resp, nil
}

func (c *Client) exitStatus() error {
	c.waitLocked()
	if c.waitE == nil {
		return errors.New("exit 0")
	}
	return c.waitE
}

// waitLocked reaps the process once; callers hold no assumption about mu.
func (c *Client) waitLocked() {
	if !c.waited {
		c.waited = true
		c.waitE = c.cmd.Wait()
	}
}

// abort kills the server and reaps it. Kill goes first so a server that
// is blocked on stdin does not get to exit 0 on the EOF from the pipe
// close: after a protocol violation the reaped status is the kill, and
// Close reports it.
func (c *Client) abort() error {
	_ = c.cmd.Process.Kill()
	_ = c.stdin.Close()
	c.waitLocked()
	return c.waitE
}

// Close ends the session: stdin is closed, the server exits on EOF, and a
// non-zero exit is returned.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if errors.Is(c.broken, ErrClosed) {
		return nil
	}
	c.broken = ErrClosed
	_ = c.stdin.Close()
	c.waitLocked()
	return c.waitE
}

// Describe returns the record view: the schema-2 record plus label,
// fingerprint, exposure, operations and findings, decoded and judged by
// checkDescribe inside Call (numbers inside meta are json.Number).
func (c *Client) Describe(ctx context.Context) (Description, error) {
	resp, err := c.Call(ctx, Request{Op: OpDescribe})
	if err != nil {
		return Description{}, err
	}
	d, err := checkDescribe(resp.Result, c.hello)
	if err != nil {
		// Unreachable after Call's own checkResult; kept so the typed
		// value can never be returned unjudged.
		return Description{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return d, nil
}

// PublicKey returns the SPKI DER and the parsed P-256 public key.
func (c *Client) PublicKey(ctx context.Context) ([]byte, *ecdsa.PublicKey, error) {
	resp, err := c.Call(ctx, Request{Op: OpPub, Format: FormatSPKIDER})
	if err != nil {
		return nil, nil, err
	}
	var pub PublicKey
	if err := json.Unmarshal(resp.Result, &pub); err != nil {
		return nil, nil, fmt.Errorf("%w: pub result: %v", ErrProtocol, err)
	}
	der, err := base64.StdEncoding.DecodeString(pub.DERBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: pub der_base64: %v", ErrProtocol, err)
	}
	ec, err := ParseSPKI(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: pub SPKI: %v", ErrProtocol, err)
	}
	return der, ec, nil
}

// PublicKeyPEM returns the SPKI as a PUBLIC KEY PEM block.
func (c *Client) PublicKeyPEM(ctx context.Context) (string, error) {
	resp, err := c.Call(ctx, Request{Op: OpPub, Format: FormatSPKIPEM})
	if err != nil {
		return "", err
	}
	var pub PublicKey
	if err := json.Unmarshal(resp.Result, &pub); err != nil {
		return "", fmt.Errorf("%w: pub result: %v", ErrProtocol, err)
	}
	return pub.PEM, nil
}

// Sign signs a 32-byte SHA-256 digest; format is FormatDERLowS, FormatRaw
// or "" for the record's default. It returns the signature bytes and the
// full result.
func (c *Client) Sign(ctx context.Context, digest []byte, format string) ([]byte, Signature, error) {
	resp, err := c.Call(ctx, Request{Op: OpSign, Digest: hex.EncodeToString(digest), Format: format})
	if err != nil {
		return nil, Signature{}, err
	}
	var sig Signature
	if err := json.Unmarshal(resp.Result, &sig); err != nil {
		return nil, Signature{}, fmt.Errorf("%w: sign result: %v", ErrProtocol, err)
	}
	raw, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return nil, Signature{}, fmt.Errorf("%w: sign signature hex: %v", ErrProtocol, err)
	}
	return raw, sig, nil
}

// Verify judges digest and signature under the bound key. A false verdict
// returns Verdict.Verified false together with the signature_invalid
// *Error; a malformed or high-S signature is an *Error without a verdict
// (high_s_refused carries the partial verdict).
func (c *Client) Verify(ctx context.Context, digest, signature []byte, format string, allowHighS bool) (Verdict, error) {
	resp, err := c.Call(ctx, Request{Op: OpVerify, Digest: hex.EncodeToString(digest), Signature: hex.EncodeToString(signature), Format: format, AllowHighS: allowHighS})
	var verdict Verdict
	if len(resp.Result) != 0 {
		if decodeErr := json.Unmarshal(resp.Result, &verdict); decodeErr != nil {
			return Verdict{}, fmt.Errorf("%w: verify result: %v", ErrProtocol, decodeErr)
		}
	}
	return verdict, err
}

// CryptoSigner adapts the bound key to crypto.Signer (crypto/x509
// CreateCertificate, CreateCertificateRequest, ...). Public is fetched now;
// Sign accepts only a 32-byte SHA-256 digest and emits X9.62 DER (low-S),
// the encoding crypto/x509 expects for ECDSA.
func (c *Client) CryptoSigner(ctx context.Context) (crypto.Signer, error) {
	_, pub, err := c.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	return &cryptoSigner{client: c, ctx: ctx, pub: pub}, nil
}

type cryptoSigner struct {
	client *Client
	ctx    context.Context
	pub    *ecdsa.PublicKey
}

func (s *cryptoSigner) Public() crypto.PublicKey { return s.pub }

func (s *cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("signerclient: the vault signs SHA-256 digests only, got %v", opts)
	}
	if len(digest) != DigestSize {
		return nil, fmt.Errorf("signerclient: digest must be %d bytes, got %d", DigestSize, len(digest))
	}
	sig, _, err := s.client.Sign(s.ctx, digest, FormatDERLowS)
	return sig, err
}
