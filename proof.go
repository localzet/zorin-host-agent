package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type OwnerProof struct {
	Version              string `json:"version"`
	Action               string `json:"action"`
	Resource             string `json:"resource"`
	HostFingerprint      string `json:"host_fingerprint"`
	PhoneFingerprint     string `json:"phone_fingerprint"`
	PhonePublicKeyDERHex string `json:"phone_public_key_der_hex"`
	Nonce                string `json:"nonce"`
	Issued               int64  `json:"issued_unix"`
	Expires              int64  `json:"expires_unix"`
	SignatureDERHex      string `json:"signature_der_hex"`
}

func ownerProofMessage(hostFP, phoneFP, actionHex, resourceHex, nonce string, issued, expires int64) []byte {
	return []byte(protocolName + "|OWNER_PROOF|" + hostFP + "|" + phoneFP + "|" + actionHex + "|" + resourceHex + "|" + nonce + "|" + strconv.FormatInt(issued, 10) + "|" + strconv.FormatInt(expires, 10))
}

func verifyOwnerProof(p OwnerProof, expectedPhoneDER []byte) error {
	if p.Version != "ZOWNER/1" {
		return errors.New("unsupported proof version")
	}
	now := time.Now().Unix()
	if p.Expires <= now {
		return errors.New("proof expired")
	}
	if p.Issued > now+30 {
		return errors.New("proof issued in the future")
	}
	pubDER, err := hex.DecodeString(p.PhonePublicKeyDERHex)
	if err != nil {
		return err
	}
	if expectedPhoneDER != nil && !strings.EqualFold(hex.EncodeToString(expectedPhoneDER), p.PhonePublicKeyDERHex) {
		return errors.New("phone public key mismatch")
	}
	parsed, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("phone key is not ECDSA")
	}
	sig, err := hex.DecodeString(p.SignatureDERHex)
	if err != nil {
		return err
	}
	ah := hex.EncodeToString([]byte(p.Action))
	rh := hex.EncodeToString([]byte(p.Resource))
	d := sha256.Sum256(ownerProofMessage(p.HostFingerprint, p.PhoneFingerprint, ah, rh, p.Nonce, p.Issued, p.Expires))
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		return errors.New("phone proof signature invalid")
	}
	return nil
}

func (p OwnerProof) JSON() string { b, _ := json.MarshalIndent(p, "", "  "); return string(b) }
func proofSummary(p OwnerProof) string {
	return fmt.Sprintf("%s %s -> %s expires=%s", p.PhoneFingerprint, p.Action, p.Resource, time.Unix(p.Expires, 0).Format(time.RFC3339))
}
