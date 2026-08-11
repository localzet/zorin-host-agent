package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestZTrust2OwnerProofFlow(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateLegacyIdentity(filepath.Join(dir, "host-identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pder, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pfp := fingerprint(pder)
	phex := hex.EncodeToString(pder)
	a := &Agent{identity: id, hostPub: id.PublicDER(), hostFP: id.Fingerprint(), cfg: Config{PairedPhones: map[string]string{pfp: phex}}, cfgPath: filepath.Join(dir, "config.json"), stateDir: dir, sessions: map[string]Session{}, live: map[string]*liveSession{}, seenADB: map[string]bool{}}
	_, _ = ensurePolicy(dir)
	srv, cli := net.Pipe()
	defer cli.Close()
	go a.handle(srv)
	r := bufio.NewReader(cli)
	hf, err := readFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hf[protocolName]; !ok {
		t.Fatalf("missing protocol: %#v", hf)
	}
	hpub, hnonce := hf["HOST_PUB"], hf["HOST_NONCE"]
	pnonce := randomHex(32)
	d := sha256.Sum256(phoneProofMessage(hnonce, pnonce, hpub, phex))
	psig, _ := ecdsa.SignASN1(rand.Reader, pk, d[:])
	if err := writeLines(cli, "PHONE_PUB "+phex, "PHONE_NONCE "+pnonce, "PHONE_SIG "+hex.EncodeToString(psig), "PHONE_STATE UNLOCKED", "END"); err != nil {
		t.Fatal(err)
	}
	af, err := readFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if af["AUTH"] != "OK" {
		t.Fatalf("auth failed: %#v", af)
	}
	// Ждём, пока хост поднимет аутентифицированное соединение до полноценной live-сессии.
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		live := len(a.live) > 0
		a.mu.Unlock()
		if live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live session did not appear")
		}
		time.Sleep(time.Millisecond)
	}
	// Запрашиваем авторизацию параллельно: запрос останется в очереди до следующего POLL телефона.
	ch := make(chan controlResponse, 1)
	go func() { ch <- a.authorize("owner.console", "local:test") }()
	time.Sleep(20 * time.Millisecond)
	if err := writeLines(cli, "POLL"); err != nil {
		t.Fatal(err)
	}
	pr, err := readFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pr["PROOF_REQUEST"]; !ok {
		t.Fatalf("expected proof request: %#v", pr)
	}
	issued, _ := strconv.ParseInt(pr["ISSUED"], 10, 64)
	expires, _ := strconv.ParseInt(pr["EXPIRES"], 10, 64)
	msg := ownerProofMessage(a.hostFP, pfp, pr["ACTION_HEX"], pr["RESOURCE_HEX"], pr["NONCE"], issued, expires)
	pd := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, pk, pd[:])
	if err := writeLines(cli, "PROOF_RESULT OK", "SIGNATURE "+hex.EncodeToString(sig), "END"); err != nil {
		t.Fatal(err)
	}
	pong, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if pong != "PONG\n" {
		t.Fatalf("unexpected pong %q", pong)
	}
	select {
	case resp := <-ch:
		if !resp.Allowed || resp.Proof == nil {
			t.Fatalf("authorize failed: %#v", resp)
		}
		if err := verifyOwnerProof(*resp.Proof, pder); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorize timed out")
	}

	// Блокировка телефона должна сохранить device trust, но убрать присутствие владельца.
	if err := writeLines(cli, "POLL LOCKED"); err != nil {
		t.Fatal(err)
	}
	pong, err = r.ReadString('\n')
	if err != nil || pong != "PONG\n" {
		t.Fatalf("locked heartbeat failed: %q %v", pong, err)
	}
	a.mu.Lock()
	sess, stillTrusted := a.sessions[pfp]
	a.mu.Unlock()
	if !stillTrusted || !sess.Trusted || sess.UserPresent {
		t.Fatalf("lock should preserve device trust but clear presence: %#v", sess)
	}
	resp := a.authorize("owner.console", "local:test")
	if resp.Allowed || resp.Reason == "" {
		t.Fatalf("locked phone should deny owner proof: %#v", resp)
	}
	_ = writeLines(cli, "BYE")

	// Дожидаемся sessionDown, чтобы goroutine не писала state-файлы уже после
	// cleanup временного каталога теста.
	deadline = time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		live := len(a.live)
		a.mu.Unlock()
		if live == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live session did not shut down")
		}
		time.Sleep(time.Millisecond)
	}
}
