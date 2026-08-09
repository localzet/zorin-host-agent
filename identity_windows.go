//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	cngTPMProvider      = "Microsoft Platform Crypto Provider"
	cngSoftwareProvider = "Microsoft Software Key Storage Provider"
	cngKeyName          = "ZorinTrustHostIdentityV2"
	cngAlgECDSAP256     = "ECDSA_P256"
	cngECCPublicBlob    = "ECCPUBLICBLOB"
)

var (
	ncrypt               = syscall.NewLazyDLL("ncrypt.dll")
	pOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	pOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	pCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	pFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	pExportKey           = ncrypt.NewProc("NCryptExportKey")
	pSignHash            = ncrypt.NewProc("NCryptSignHash")
	pFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

type cngIdentity struct {
	provider     uintptr
	key          uintptr
	providerName string
	keyName      string
	der          []byte
	fp           string
}

func cngStatus(op string, r uintptr) error {
	if uint32(r) == 0 {
		return nil
	}
	return fmt.Errorf("%s failed: SECURITY_STATUS 0x%08X", op, uint32(r))
}

func wstr(s string) (*uint16, error) { return syscall.UTF16PtrFromString(s) }

func openCNGIdentity(providerName, keyName string, create bool) (*cngIdentity, error) {
	pProvider, err := wstr(providerName)
	if err != nil {
		return nil, err
	}
	pKeyName, err := wstr(keyName)
	if err != nil {
		return nil, err
	}
	var hp uintptr
	r, _, _ := pOpenStorageProvider.Call(uintptr(unsafe.Pointer(&hp)), uintptr(unsafe.Pointer(pProvider)), 0)
	if err := cngStatus("NCryptOpenStorageProvider", r); err != nil {
		return nil, err
	}
	cleanupProvider := true
	defer func() {
		if cleanupProvider && hp != 0 {
			pFreeObject.Call(hp)
		}
	}()

	var hk uintptr
	r, _, _ = pOpenKey.Call(hp, uintptr(unsafe.Pointer(&hk)), uintptr(unsafe.Pointer(pKeyName)), 0, 0)
	if uint32(r) != 0 {
		if !create {
			return nil, cngStatus("NCryptOpenKey", r)
		}
		pAlg, _ := wstr(cngAlgECDSAP256)
		r, _, _ = pCreatePersistedKey.Call(hp, uintptr(unsafe.Pointer(&hk)), uintptr(unsafe.Pointer(pAlg)), uintptr(unsafe.Pointer(pKeyName)), 0, 0)
		if err := cngStatus("NCryptCreatePersistedKey", r); err != nil {
			return nil, err
		}
		r, _, _ = pFinalizeKey.Call(hk, 0)
		if err := cngStatus("NCryptFinalizeKey", r); err != nil {
			pFreeObject.Call(hk)
			return nil, err
		}
	}

	id := &cngIdentity{provider: hp, key: hk, providerName: providerName, keyName: keyName}
	der, err := id.exportPublicDER()
	if err != nil {
		pFreeObject.Call(hk)
		return nil, err
	}
	id.der, id.fp = der, fingerprint(der)
	cleanupProvider = false
	return id, nil
}

func (i *cngIdentity) PublicDER() []byte   { return append([]byte(nil), i.der...) }
func (i *cngIdentity) Fingerprint() string { return i.fp }
func (i *cngIdentity) Provider() string {
	if i.providerName == cngTPMProvider {
		return "windows-cng/tpm"
	}
	return "windows-cng/software"
}

func (i *cngIdentity) exportPublicDER() ([]byte, error) {
	bt, _ := wstr(cngECCPublicBlob)
	var n uint32
	r, _, _ := pExportKey.Call(i.key, 0, uintptr(unsafe.Pointer(bt)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := cngStatus("NCryptExportKey(size)", r); err != nil {
		return nil, err
	}
	if n < 8 || n > 4096 {
		return nil, errors.New("invalid CNG public blob size")
	}
	b := make([]byte, n)
	r, _, _ = pExportKey.Call(i.key, 0, uintptr(unsafe.Pointer(bt)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	if err := cngStatus("NCryptExportKey", r); err != nil {
		return nil, err
	}
	cb := binary.LittleEndian.Uint32(b[4:8])
	if cb == 0 || int(8+2*cb) > len(b) {
		return nil, errors.New("malformed CNG ECCPUBLICBLOB")
	}
	x := new(big.Int).SetBytes(b[8 : 8+cb])
	y := new(big.Int).SetBytes(b[8+cb : 8+2*cb])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("CNG public key is not P-256")
	}
	return x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y})
}

func (i *cngIdentity) SignDigest(hash []byte) ([]byte, error) {
	if len(hash) == 0 {
		return nil, errors.New("empty digest")
	}
	var n uint32
	r, _, _ := pSignHash.Call(i.key, 0, uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := cngStatus("NCryptSignHash(size)", r); err != nil {
		return nil, err
	}
	if n == 0 || n > 512 {
		return nil, errors.New("invalid CNG signature size")
	}
	out := make([]byte, n)
	r, _, _ = pSignHash.Call(i.key, 0, uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), 0)
	if err := cngStatus("NCryptSignHash", r); err != nil {
		return nil, err
	}
	return rawECDSAToASN1(out[:n])
}

func loadHostIdentity(stateDir string) (HostIdentity, error) {
	if m, ok := readIdentityMeta(stateDir); ok && m.Type == "cng" {
		provider := m.Provider
		if provider == "" {
			provider = cngTPMProvider
		}
		keyName := m.KeyName
		if keyName == "" {
			keyName = cngKeyName
		}
		return openCNGIdentity(provider, keyName, false)
	}
	legacy := filepath.Join(stateDir, "host-identity.pem")
	if _, err := os.Stat(legacy); err == nil {
		return loadOrCreateLegacyIdentity(legacy)
	}
	if id, err := openCNGIdentity(cngTPMProvider, cngKeyName, true); err == nil {
		_ = writeIdentityMeta(stateDir, identityMeta{Type: "cng", Provider: cngTPMProvider, KeyName: cngKeyName})
		return id, nil
	}
	if id, err := openCNGIdentity(cngSoftwareProvider, cngKeyName, true); err == nil {
		_ = writeIdentityMeta(stateDir, identityMeta{Type: "cng", Provider: cngSoftwareProvider, KeyName: cngKeyName})
		return id, nil
	}
	return loadOrCreateLegacyIdentity(legacy)
}

func migrateHostIdentityToTPM(stateDir string) (HostIdentity, error) {
	id, err := openCNGIdentity(cngTPMProvider, cngKeyName, true)
	if err != nil {
		return nil, err
	}
	if err := writeIdentityMeta(stateDir, identityMeta{Type: "cng", Provider: cngTPMProvider, KeyName: cngKeyName}); err != nil {
		return nil, err
	}
	return id, nil
}
