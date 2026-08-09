package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"
)

func TestOwnerProofVerification(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	p := OwnerProof{Version: "ZOWNER/1", Action: "owner.console", Resource: "local:test", HostFingerprint: "HOST", PhoneFingerprint: fingerprint(der), PhonePublicKeyDERHex: hex.EncodeToString(der), Nonce: randomHex(32), Issued: now, Expires: now + 30}
	ah := hex.EncodeToString([]byte(p.Action))
	rh := hex.EncodeToString([]byte(p.Resource))
	d := sha256.Sum256(ownerProofMessage(p.HostFingerprint, p.PhoneFingerprint, ah, rh, p.Nonce, p.Issued, p.Expires))
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	p.SignatureDERHex = hex.EncodeToString(sig)
	if err := verifyOwnerProof(p, der); err != nil {
		t.Fatal(err)
	}
	p.Resource = "local:tampered"
	if err := verifyOwnerProof(p, der); err == nil {
		t.Fatal("tampered proof accepted")
	}
}
