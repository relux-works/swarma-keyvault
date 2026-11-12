package namecoinpsbt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// signingAccount is used only inside the linked custody engine after genuine
// native review/unseal. Never copy it, serialize it or return it through IPC.
// Its owned buffers and supported scalar objects are cleared explicitly;
// opaque runtime/library/OS copies are not claimed universally erasable.
type signingAccount struct {
	scalar btcec.ModNScalar
	chain  [32]byte
	closed bool
}

func (*signingAccount) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<confined Namecoin account>")
}
func (a *signingAccount) clear() {
	if a != nil {
		a.scalar.Zero()
		clear(a.chain[:])
		a.closed = true
	}
}
func loadSigningAccount(material []byte, expectedPoint [33]byte, expectedChain [32]byte) (*signingAccount, error) {
	a := new(signingAccount)
	admitted := false
	defer func() {
		if !admitted {
			a.clear()
		}
	}()
	if len(material) != 64 || a.scalar.SetByteSlice(material[:32]) || a.scalar.IsZero() {
		a.clear()
		return nil, failure(namecoinwire.AccountMismatch)
	}
	copy(a.chain[:], material[32:])
	key := btcec.PrivKeyFromScalar(&a.scalar)
	defer key.Zero()
	pub := key.PubKey().SerializeCompressed()
	key.Zero()
	if subtle.ConstantTimeCompare(a.chain[:], expectedChain[:]) != 1 || !bytes.Equal(pub, expectedPoint[:]) {
		a.clear()
		return nil, failure(namecoinwire.AccountMismatch)
	}
	admitted = true
	return a, nil
}
func (a *signingAccount) child(index uint32) (*signingAccount, error) {
	if a == nil || a.closed || index >= 0x80000000 {
		return nil, failure(namecoinwire.PathRefused)
	}
	key := btcec.PrivKeyFromScalar(&a.scalar)
	defer key.Zero()
	pub := key.PubKey().SerializeCompressed()
	key.Zero()
	mac := hmac.New(sha512.New, a.chain[:])
	_, _ = mac.Write(pub)
	var childBytes [4]byte
	binary.BigEndian.PutUint32(childBytes[:], index)
	_, _ = mac.Write(childBytes[:])
	material := mac.Sum(nil)
	defer clear(material)
	return addPrivateChild(a, material)
}
func addPrivateChild(parent *signingAccount, material []byte) (*signingAccount, error) {
	if parent == nil || parent.closed || len(material) != 64 {
		return nil, failure(namecoinwire.PathRefused)
	}
	var delta btcec.ModNScalar
	defer delta.Zero()
	if delta.SetByteSlice(material[:32]) {
		return nil, failure(namecoinwire.PathRefused)
	}
	child := new(signingAccount)
	child.scalar.Set(&parent.scalar)
	child.scalar.Add(&delta)
	if child.scalar.IsZero() {
		child.clear()
		return nil, failure(namecoinwire.PathRefused)
	}
	copy(child.chain[:], material[32:])
	return child, nil
}

// signConfined is not a public digest or plaintext-account operation. Its
// caller must be the same-process custody lifecycle AFTER durable dispatch
// and protected-anchor readback, retaining the gate through secret cleanup.
func (c Candidate) signConfined(account *signingAccount, selected Selection) ([][]byte, error) {
	if len(c.digests) == 0 || account == nil || account.closed {
		return nil, failure(namecoinwire.AccountMismatch)
	}
	signatures := make([][]byte, len(c.digests))
	for i, view := range c.view.Inputs {
		if !namecoinwire.Path(view.Path) {
			return nil, failure(namecoinwire.PathRefused)
		}
		parts := strings.Split(view.Path, "/")
		branchIndex, _ := strconv.ParseUint(parts[4], 10, 32)
		childIndex, _ := strconv.ParseUint(parts[5], 10, 32)
		child, err := func() (*signingAccount, error) {
			branch, err := account.child(uint32(branchIndex))
			if err != nil {
				return nil, err
			}
			defer branch.clear()
			return branch.child(uint32(childIndex))
		}()
		if err != nil {
			return nil, err
		}
		// Keep per-input secret objects inside this frame so even a recovered
		// boundary panic runs their clearing defers before it reports UNKNOWN.
		err = func() error {
			defer child.clear()
			key := btcec.PrivKeyFromScalar(&child.scalar)
			defer key.Zero()
			if !bytes.Equal(key.PubKey().SerializeCompressed(), c.packet.inputs[i].origin.key[:]) {
				return failure(namecoinwire.AccountMismatch)
			}
			sig := ecdsa.Sign(key, c.digests[i][:])
			signatures[i] = append(sig.Serialize(), 1)
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	if err := c.VerifySignatures(signatures); err != nil {
		return nil, err
	}
	if err := c.CheckFinalFeeRate(signatures, selected); err != nil {
		return nil, err
	}
	return signatures, nil
}
