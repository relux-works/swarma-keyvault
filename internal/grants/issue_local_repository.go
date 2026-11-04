package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

var errRequesterMismatch = errors.New("requester-key-mismatch")

const localMatrixDisclosure = "Ни одно устройство Matrix не аутентифицировано. encrypted-dm — только заявленная метка; этот локальный путь ничего не шифрует и не доставляет через Matrix."

func localRepositoryReview(payload []byte, digest [32]byte, organization, name string) (string, error) {
	certificate, err := parseLocalCertificateProjection(payload)
	if err != nil {
		return "", err
	}
	var display bytes.Buffer
	if err := json.Indent(&display, payload, "", "  "); err != nil {
		return "", errBadEncoding
	}
	return fmt.Sprintf("Разрешается одно локальное создание приватного репозитория %s/%s и парное удаление; удаление не выполняется.\nПодпись ещё не выполнена.\n%s\nЗаявленный account/device: %s / %s\nRequester SPKI SHA256: %x\nDomain: swarma-grants/local-certificate/1\nSHA256(domain + LF + exact payload): %x\n%s\n", organization, name, localMatrixDisclosure, certificate.subject.accountMXID, certificate.subject.deviceID, certificate.requesterHash, digest, display.Bytes()), nil
}

// NewLocalRepositoryIssuance constrains the signed hash against an independent
// expected requester key before any private operation. It never enrolls a key.
func NewLocalRepositoryIssuance(payload []byte, owner string, public, requester []byte, organization, name string) (*RepositoryIssuance, error) {
	certificate, err := parseLocalCertificateProjection(payload)
	if err != nil {
		return nil, err
	}
	if err := validateRepositoryScope(certificate.certificateProjection, owner, public, organization, name); err != nil {
		return nil, err
	}
	if _, err := localPublicKey(requester); err != nil {
		return nil, err
	}
	if bytes.Equal(public, requester) || sha256.Sum256(requester) != certificate.requesterHash {
		return nil, errRequesterMismatch
	}
	digest, err := domainDigest(localCertificateDomain, payload)
	if err != nil {
		return nil, err
	}
	review, err := localRepositoryReview(payload, digest, organization, name)
	if err != nil {
		return nil, err
	}
	return &RepositoryIssuance{payload: bytes.Clone(payload), public: bytes.Clone(public), owner: owner, review: review, digest: digest, profile: localCertificateEnvelopeWire}, nil
}
