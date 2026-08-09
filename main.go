package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	version      = "0.1.0"
	listenAddr   = "127.0.0.1:47472"
	androidPkg   = "dev.zorin.nativelab"
	androidAct   = "android.app.NativeActivity"
	protocolName = "ZTRUST/1"
)

type Config struct {
	PairedPhones map[string]string `json:"paired_phones"` // fingerprint -> PKIX DER hex
}

type Session struct {
	Trusted          bool      `json:"trusted"`
	HostFingerprint  string    `json:"host_fingerprint"`
	PhoneFingerprint string    `json:"phone_fingerprint"`
	Since            time.Time `json:"since"`
	LastSeen         time.Time `json:"last_seen"`
	Policy           string    `json:"policy"`
}

type Agent struct {
	hostKey   *ecdsa.PrivateKey
	hostPub   []byte
	hostFP    string
	cfg       Config
	cfgPath   string
	stateDir  string
	pairOnce  bool
	onTrust   string
	onUntrust string

	mu       sync.Mutex
	sessions map[string]Session
	seenADB  map[string]bool
}

func main() {
	daemon := flag.NewFlagSet("daemon", flag.ExitOnError)
	pairOnce := daemon.Bool("pair-once", false, "allow the next cryptographically valid, phone-approved device to pair")
	onTrust := daemon.String("on-trust", "", "optional local command to run when the first trusted USB session appears")
	onUntrust := daemon.String("on-untrust", "", "optional local command to run when the last trusted USB session disappears")
	noADB := daemon.Bool("no-adb-watch", false, "listen only; do not configure adb reverse or wake the Android app")

	cmd := "daemon"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	a, err := loadAgent()
	if err != nil {
		fatal(err)
	}

	switch cmd {
	case "daemon":
		_ = daemon.Parse(args)
		a.pairOnce = *pairOnce
		a.onTrust, a.onUntrust = *onTrust, *onUntrust
		fmt.Printf("Zorin Host Agent %s\n", version)
		fmt.Printf("Host identity: %s\n", a.hostFP)
		fmt.Printf("Listen: %s\n", listenAddr)
		if a.pairOnce {
			fmt.Println("PAIR WINDOW: the next phone approved on-device may be enrolled")
		}
		if !*noADB {
			go a.adbWatcher()
		}
		if err := a.serve(); err != nil {
			fatal(err)
		}
	case "status":
		fmt.Printf("Zorin Host Agent %s\nHost identity: %s\n", version, a.hostFP)
		fps := make([]string, 0, len(a.cfg.PairedPhones))
		for fp := range a.cfg.PairedPhones {
			fps = append(fps, fp)
		}
		sort.Strings(fps)
		fmt.Printf("Paired phones: %d\n", len(fps))
		for _, fp := range fps {
			fmt.Printf("  %s\n", fp)
		}
		if b, err := os.ReadFile(filepath.Join(a.stateDir, "session.json")); err == nil {
			fmt.Printf("Active state:\n%s\n", b)
		} else {
			fmt.Println("Active state: none")
		}
	case "unpair-all":
		a.cfg.PairedPhones = map[string]string{}
		if err := a.saveConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("All paired phones removed.")
	case "fingerprint":
		fmt.Println(a.hostFP)
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s [daemon|status|fingerprint|unpair-all] [options]\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
}

func loadAgent() (*Agent, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	stateDir := filepath.Join(dir, "ZorinTrust")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}

	keyPath := filepath.Join(stateDir, "host-identity.pem")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	cfgPath := filepath.Join(stateDir, "config.json")
	cfg := Config{PairedPhones: map[string]string{}}
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
		if cfg.PairedPhones == nil {
			cfg.PairedPhones = map[string]string{}
		}
	}
	a := &Agent{hostKey: key, hostPub: pub, hostFP: fingerprint(pub), cfg: cfg, cfgPath: cfgPath, stateDir: stateDir, sessions: map[string]Session{}, seenADB: map[string]bool{}}
	return a, nil
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid host identity PEM")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func (a *Agent) saveConfig() error {
	b, _ := json.MarshalIndent(a.cfg, "", "  ")
	return os.WriteFile(a.cfgPath, b, 0600)
}

func fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	// 128-bit display fingerprint is enough for human comparison while the full key is stored/verified.
	s := strings.ToUpper(hex.EncodeToString(h[:16]))
	parts := make([]string, 0, 8)
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, ":")
}

func (a *Agent) serve() error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go a.handle(c)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeLines(w io.Writer, lines ...string) error {
	for _, s := range lines {
		if _, err := io.WriteString(w, s+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r *bufio.Reader) (map[string]string, error) {
	out := map[string]string{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "END" {
			return out, nil
		}
		if line == "" {
			continue
		}
		p := strings.IndexByte(line, ' ')
		if p < 1 {
			out[line] = ""
		} else {
			out[line[:p]] = line[p+1:]
		}
	}
}

func phoneProofMessage(hostNonce, phoneNonce, hostPubHex, phonePubHex string) []byte {
	return []byte(protocolName + "|PHONE|" + hostNonce + "|" + phoneNonce + "|" + hostPubHex + "|" + phonePubHex)
}
func hostProofMessage(hostNonce, phoneNonce, hostPubHex, phonePubHex string) []byte {
	return []byte(protocolName + "|HOST|" + phoneNonce + "|" + hostNonce + "|" + phonePubHex + "|" + hostPubHex)
}

func (a *Agent) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	hostNonce := randomHex(32)
	hostPubHex := hex.EncodeToString(a.hostPub)
	hostName, _ := os.Hostname()
	if hostName == "" {
		hostName = runtime.GOOS
	}
	if err := writeLines(c, protocolName, "HOST_NAME "+sanitize(hostName), "HOST_PUB "+hostPubHex, "HOST_NONCE "+hostNonce, "END"); err != nil {
		return
	}

	r := bufio.NewReader(c)
	f, err := readFrame(r)
	if err != nil {
		return
	}
	phonePubHex, phoneNonce, phoneSigHex := f["PHONE_PUB"], f["PHONE_NONCE"], f["PHONE_SIG"]
	if phonePubHex == "" || phoneNonce == "" || phoneSigHex == "" {
		_ = writeLines(c, "AUTH FAIL malformed", "END")
		return
	}
	phoneDER, err := hex.DecodeString(phonePubHex)
	if err != nil {
		_ = writeLines(c, "AUTH FAIL phone-pub", "END")
		return
	}
	parsed, err := x509.ParsePKIXPublicKey(phoneDER)
	if err != nil {
		_ = writeLines(c, "AUTH FAIL phone-pub", "END")
		return
	}
	phonePub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		_ = writeLines(c, "AUTH FAIL phone-key-type", "END")
		return
	}
	sig, err := hex.DecodeString(phoneSigHex)
	if err != nil {
		_ = writeLines(c, "AUTH FAIL phone-sig", "END")
		return
	}
	digest := sha256.Sum256(phoneProofMessage(hostNonce, phoneNonce, hostPubHex, phonePubHex))
	if !ecdsa.VerifyASN1(phonePub, digest[:], sig) {
		_ = writeLines(c, "AUTH FAIL bad-phone-signature", "END")
		return
	}

	phoneFP := fingerprint(phoneDER)
	a.mu.Lock()
	pairedHex, paired := a.cfg.PairedPhones[phoneFP]
	if paired && !strings.EqualFold(pairedHex, phonePubHex) {
		paired = false
	}
	if !paired && a.pairOnce {
		a.cfg.PairedPhones[phoneFP] = phonePubHex
		a.pairOnce = false
		_ = a.saveConfig()
		paired = true
		fmt.Printf("PAIRED phone %s\n", phoneFP)
	}
	a.mu.Unlock()
	if !paired {
		_ = writeLines(c, "AUTH PAIR_REQUIRED", "PHONE_FINGERPRINT "+phoneFP, "END")
		fmt.Printf("Rejected unpaired phone %s (restart with --pair-once to enroll)\n", phoneFP)
		return
	}

	hd := sha256.Sum256(hostProofMessage(hostNonce, phoneNonce, hostPubHex, phonePubHex))
	hostSig, err := ecdsa.SignASN1(rand.Reader, a.hostKey, hd[:])
	if err != nil {
		return
	}
	if err := writeLines(c, "AUTH OK", "HOST_SIG "+hex.EncodeToString(hostSig), "HOST_FINGERPRINT "+a.hostFP, "PHONE_FINGERPRINT "+phoneFP, "POLICY owner-workstation", "END"); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})
	a.sessionUp(phoneFP)
	defer a.sessionDown(phoneFP)
	for {
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "PING" {
			a.sessionTouch(phoneFP)
			if err := writeLines(c, "PONG"); err != nil {
				return
			}
		} else if line == "BYE" {
			return
		} else {
			_ = writeLines(c, "ERR fixed-protocol-only")
		}
	}
}

func (a *Agent) sessionUp(phoneFP string) {
	a.mu.Lock()
	wasEmpty := len(a.sessions) == 0
	now := time.Now()
	a.sessions[phoneFP] = Session{Trusted: true, HostFingerprint: a.hostFP, PhoneFingerprint: phoneFP, Since: now, LastSeen: now, Policy: "owner-workstation"}
	a.writeSessionLocked()
	a.mu.Unlock()
	fmt.Printf("TRUSTED session UP phone=%s\n", phoneFP)
	if wasEmpty {
		runHook(a.onTrust)
	}
}
func (a *Agent) sessionTouch(phoneFP string) {
	a.mu.Lock()
	s := a.sessions[phoneFP]
	s.LastSeen = time.Now()
	a.sessions[phoneFP] = s
	a.writeSessionLocked()
	a.mu.Unlock()
}
func (a *Agent) sessionDown(phoneFP string) {
	a.mu.Lock()
	delete(a.sessions, phoneFP)
	nowEmpty := len(a.sessions) == 0
	a.writeSessionLocked()
	a.mu.Unlock()
	fmt.Printf("TRUSTED session DOWN phone=%s\n", phoneFP)
	if nowEmpty {
		runHook(a.onUntrust)
	}
}
func (a *Agent) writeSessionLocked() {
	p := filepath.Join(a.stateDir, "session.json")
	if len(a.sessions) == 0 {
		_ = os.Remove(p)
		return
	}
	list := make([]Session, 0, len(a.sessions))
	for _, s := range a.sessions {
		list = append(list, s)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(p, b, 0600)
}

func runHook(command string) {
	if strings.TrimSpace(command) == "" {
		return
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go func() {
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "hook failed: %v\n", err)
		}
	}()
}

func (a *Agent) adbWatcher() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		a.adbSweep()
		<-ticker.C
	}
}
func (a *Agent) adbSweep() {
	if _, err := exec.LookPath("adb"); err != nil {
		return
	}
	out, err := exec.Command("adb", "devices").Output()
	if err != nil {
		return
	}
	current := map[string]bool{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "device" {
			continue
		}
		serial := f[0]
		current[serial] = true
		_ = exec.Command("adb", "-s", serial, "reverse", "tcp:47472", "tcp:47472").Run()
		a.mu.Lock()
		first := !a.seenADB[serial]
		a.seenADB[serial] = true
		a.mu.Unlock()
		if first {
			fmt.Printf("ADB device connected: %s; reverse installed\n", serial)
			// Wake the NativeActivity. Paired sessions require no tap; an unknown host still requires explicit APPROVE on the phone.
			_ = exec.Command("adb", "-s", serial, "shell", "am", "start", "-n", androidPkg+"/"+androidAct, "--ez", "dev.zorin.trust.autoconnect", "true").Run()
		}
	}
	a.mu.Lock()
	for s := range a.seenADB {
		if !current[s] {
			delete(a.seenADB, s)
			fmt.Printf("ADB device disconnected: %s\n", s)
		}
	}
	a.mu.Unlock()
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
