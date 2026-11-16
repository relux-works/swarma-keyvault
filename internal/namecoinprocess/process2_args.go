package namecoinprocess

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var errInvalidProcess2 = errors.New("invalid process2 invocation")

// Process2Invocation is the closed, explicit sign-psbt contract/2 selection.
// It preserves the process/1 flag grammar without changing that parser.
type Process2Invocation struct {
	args Args
	argv []string
}

// Process2AttemptInputs are independently frozen public values supplied by the
// trusted parent. They are checked against parsed argv before launch, so the
// parent binding is not derived from an argv assertion.
type Process2AttemptInputs struct {
	Mode                 Mode
	Group, Account       string
	ProfileSHA256        [32]byte
	OperationInputSHA256 [32]byte
}

func (i Process2AttemptInputs) binding() [32]byte {
	var binding [32]byte
	h := sha256.New()
	_, _ = h.Write([]byte("keyvault-namecoin-process-observation/1\x00"))
	for _, field := range [][]byte{[]byte(i.Mode), []byte(i.Group), []byte(i.Account), i.ProfileSHA256[:], i.OperationInputSHA256[:]} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(field)
	}
	copy(binding[:], h.Sum(nil))
	return binding
}

func ParseProcess2Args(argv []string) (Process2Invocation, error) {
	if len(argv) < 2 || argv[0] != "namecoin" || Mode(argv[1]) != SignPSBT || (len(argv)-2)%2 != 0 {
		return Process2Invocation{}, errInvalidProcess2
	}
	canonical := append([]string(nil), argv...)
	contractCount := 0
	for i := 2; i < len(canonical); i += 2 {
		if canonical[i] == "--process-contract" {
			contractCount++
			if canonical[i+1] != "2" {
				return Process2Invocation{}, errInvalidProcess2
			}
			canonical[i+1] = "1"
		}
	}
	if contractCount != 1 {
		return Process2Invocation{}, errInvalidProcess2
	}
	args, err := ParseArgs(canonical)
	if err != nil || args.Mode != SignPSBT {
		return Process2Invocation{}, errInvalidProcess2
	}
	return Process2Invocation{args: args, argv: append([]string(nil), argv...)}, nil
}

func (i Process2Invocation) Args() Args { return i.args }

func (i Process2Invocation) Argv() []string { return append([]string(nil), i.argv...) }
