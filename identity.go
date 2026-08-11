package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

type HostIdentity interface {
	PublicDER() []byte
	Fingerprint() string
	Provider() string
	SignDigest([]byte) ([]byte, error)
}

type identityMeta struct {
	Type     string `json:"type"`
	Provider string `json:"provider,omitempty"`
	KeyName  string `json:"key_name,omitempty"`
}

type legacyIdentity struct {
	key *ecdsa.PrivateKey
	der []byte
	fp  string
}

func (i *legacyIdentity) PublicDER() []byte   { return append([]byte(nil), i.der...) }
func (i *legacyIdentity) Fingerprint() string { return i.fp }
func (i *legacyIdentity) Provider() string    { return "legacy-pem/software" }
func (i *legacyIdentity) SignDigest(d []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, i.key, d)
}

type ephemeralIdentity struct {
	key *ecdsa.PrivateKey
	der []byte
	fp  string
}

func (i *ephemeralIdentity) PublicDER() []byte {
	return append([]byte(nil), i.der...)
}

func (i *ephemeralIdentity) Fingerprint() string {
	return i.fp
}

func (i *ephemeralIdentity) Provider() string {
	return "portable/ephemeral"
}

func (i *ephemeralIdentity) SignDigest(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, i.key, digest)
}

func newEphemeralIdentity() (HostIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &ephemeralIdentity{
		key: key,
		der: der,
		fp:  fingerprint(der),
	}, nil
}

func fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	s := strings.ToUpper(hex.EncodeToString(h[:16]))
	parts := make([]string, 0, 8)
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, ":")
}

func loadOrCreateLegacyIdentity(path string) (HostIdentity, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid host identity PEM")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		return &legacyIdentity{key: k, der: der, fp: fingerprint(der)}, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	derPriv, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derPriv}), 0600); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return &legacyIdentity{key: k, der: der, fp: fingerprint(der)}, nil
}

func readIdentityMeta(stateDir string) (identityMeta, bool) {
	b, err := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	if err != nil {
		return identityMeta{}, false
	}
	var m identityMeta
	if json.Unmarshal(b, &m) != nil {
		return identityMeta{}, false
	}
	return m, true
}

func writeIdentityMeta(stateDir string, m identityMeta) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(filepath.Join(stateDir, "identity.json"), b, 0600)
}

type ecdsaASN1Signature struct{ R, S *big.Int }

func rawECDSAToASN1(raw []byte) ([]byte, error) {
	var parsed ecdsaASN1Signature
	if rest, err := asn1.Unmarshal(raw, &parsed); err == nil && len(rest) == 0 && parsed.R != nil && parsed.S != nil {
		return append([]byte(nil), raw...), nil
	}
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, errors.New("unexpected ECDSA signature size")
	}
	n := len(raw) / 2
	return asn1.Marshal(ecdsaASN1Signature{R: new(big.Int).SetBytes(raw[:n]), S: new(big.Int).SetBytes(raw[n:])})
}
