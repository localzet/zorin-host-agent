package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version      = "0.3.1"
	listenAddr   = "127.0.0.1:47472"
	controlAddr  = "127.0.0.1:47473"
	androidPkg   = "dev.zorin.trustruntime"
	androidAct   = "android.app.NativeActivity"
	androidSvc   = "dev.zorin.trustruntime.TrustService"
	protocolName = "ZTRUST/2"
)

type Config struct {
	PairedPhones map[string]string `json:"paired_phones"`
}

type Session struct {
	Trusted              bool      `json:"trusted"`
	HostFingerprint      string    `json:"host_fingerprint"`
	PhoneFingerprint     string    `json:"phone_fingerprint"`
	Since                time.Time `json:"since"`
	LastSeen             time.Time `json:"last_seen"`
	Policy               string    `json:"policy"`
	HostIdentityProvider string    `json:"host_identity_provider"`
	UserPresent          bool      `json:"user_present"`
}

type proofRequest struct {
	action   string
	resource string
	ttl      int
	result   chan proofResult
}
type proofResult struct {
	proof OwnerProof
	err   error
}
type liveSession struct {
	phoneFP     string
	phoneDER    []byte
	req         chan proofRequest
	userPresent bool
}

type Agent struct {
	identity     HostIdentity
	hostPub      []byte
	hostFP       string
	cfg          Config
	cfgPath      string
	stateDir     string
	pairOnce     bool
	onTrust      string
	onUntrust    string
	adbSerial    string
	controlToken string

	mu       sync.Mutex
	sessions map[string]Session
	live     map[string]*liveSession
	seenADB  map[string]bool
	lastWake map[string]time.Time
}

func main() {
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
		fs := flag.NewFlagSet("daemon", flag.ExitOnError)
		pairOnce := fs.Bool("pair-once", false, "allow the next cryptographically valid, phone-approved device to pair")
		onTrust := fs.String("on-trust", "", "optional local command to run when the first trusted USB session appears")
		onUntrust := fs.String("on-untrust", "", "optional local command to run when the last trusted USB session disappears")
		noADB := fs.Bool("no-adb-watch", false, "listen only; do not configure adb reverse or wake the Android app")
		serial := fs.String("serial", "", "limit ADB watcher to one device serial (adb -s <serial>)")
		_ = fs.Parse(args)
		a.pairOnce = *pairOnce
		a.onTrust = *onTrust
		a.onUntrust = *onUntrust
		a.adbSerial = strings.TrimSpace(*serial)
		fmt.Printf("Zorin Host Agent %s\n", version)
		fmt.Printf("Host identity: %s\n", a.hostFP)
		fmt.Printf("Identity provider: %s\n", a.identity.Provider())
		fmt.Printf("Trust listen: %s\nControl API: %s\n", listenAddr, controlAddr)
		if a.adbSerial != "" {
			fmt.Printf("ADB target: %s\n", a.adbSerial)
		}
		if a.pairOnce {
			fmt.Println("PAIR WINDOW: the next phone approved on-device may be enrolled")
		}
		if !*noADB {
			go a.adbWatcher()
		}
		go func() {
			if err := a.serveControl(); err != nil {
				fmt.Fprintln(os.Stderr, "control error:", err)
			}
		}()
		if err := a.serve(); err != nil {
			fatal(err)
		}
	case "status":
		a.printStatus()
	case "fingerprint":
		fmt.Println(a.hostFP)
	case "policy":
		p := filepath.Join(a.stateDir, "policy.json")
		_, _ = ensurePolicy(a.stateDir)
		fmt.Println(p)
		if b, err := os.ReadFile(p); err == nil {
			fmt.Println(string(b))
		}
	case "authorize", "credential":
		runAuthorizeCLI(a, args)
	case "gate":
		runGateCLI(a, args)
	case "identity":
		runIdentityCLI(a, args)
	case "unpair-all":
		a.cfg.PairedPhones = map[string]string{}
		if err := a.saveConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("All paired phones removed.")
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s [daemon|status|authorize|credential|gate|policy|identity|fingerprint|unpair-all|version] [options]\n", filepath.Base(os.Args[0]))
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
	id, err := loadHostIdentity(stateDir)
	if err != nil {
		return nil, err
	}
	pub := id.PublicDER()
	cfgPath := filepath.Join(stateDir, "config.json")
	cfg := Config{PairedPhones: map[string]string{}}
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
		if cfg.PairedPhones == nil {
			cfg.PairedPhones = map[string]string{}
		}
	}
	token, err := ensureControlToken(stateDir)
	if err != nil {
		return nil, err
	}
	_, _ = ensurePolicy(stateDir)
	return &Agent{identity: id, hostPub: pub, hostFP: id.Fingerprint(), cfg: cfg, cfgPath: cfgPath, stateDir: stateDir, controlToken: token, sessions: map[string]Session{}, live: map[string]*liveSession{}, seenADB: map[string]bool{}, lastWake: map[string]time.Time{}}, nil
}

func ensureControlToken(stateDir string) (string, error) {
	p := filepath.Join(stateDir, "control.token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	t := randomHex(32)
	if err := os.WriteFile(p, []byte(t+"\n"), 0600); err != nil {
		return "", err
	}
	return t, nil
}
func (a *Agent) saveConfig() error {
	b, _ := json.MarshalIndent(a.cfg, "", "  ")
	return os.WriteFile(a.cfgPath, b, 0600)
}

func (a *Agent) printStatus() {
	fmt.Printf("Zorin Host Agent %s\nHost identity: %s\nIdentity provider: %s\n", version, a.hostFP, a.identity.Provider())
	fps := make([]string, 0, len(a.cfg.PairedPhones))
	for fp := range a.cfg.PairedPhones {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	fmt.Printf("Paired phones: %d\n", len(fps))
	for _, fp := range fps {
		fmt.Printf("  %s\n", fp)
	}
	fmt.Printf("Policy: %s\n", filepath.Join(a.stateDir, "policy.json"))
	fmt.Printf("Control API: %s (token file protected in state dir)\n", controlAddr)
	if b, err := os.ReadFile(filepath.Join(a.stateDir, "session.json")); err == nil {
		fmt.Printf("Active state:\n%s\n", b)
	} else {
		fmt.Println("Active state: none")
	}
	if b, err := os.ReadFile(filepath.Join(a.stateDir, "owner-mode.json")); err == nil {
		fmt.Printf("Owner mode:\n%s\n", b)
	} else {
		fmt.Println("Owner mode: locked")
	}
}

func (a *Agent) serve() error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "address already in use") || strings.Contains(strings.ToLower(err.Error()), "only one usage") {
			return fmt.Errorf("another Zorin Host Agent is already listening on %s; stop/restart it or use the pairing script: %w", listenAddr, err)
		}
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
	if writeLines(c, protocolName, "HOST_NAME "+sanitize(hostName), "HOST_PUB "+hostPubHex, "HOST_NONCE "+hostNonce, "HOST_IDENTITY "+a.identity.Provider(), "END") != nil {
		return
	}
	r := bufio.NewReader(c)
	f, err := readFrame(r)
	if err != nil {
		return
	}
	phonePubHex, phoneNonce, phoneSigHex := f["PHONE_PUB"], f["PHONE_NONCE"], f["PHONE_SIG"]
	phoneState := f["PHONE_STATE"]
	initialPresence := !strings.EqualFold(phoneState, "LOCKED")
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
	hostSig, err := a.identity.SignDigest(hd[:])
	if err != nil {
		return
	}
	if writeLines(c, "AUTH OK", "HOST_SIG "+hex.EncodeToString(hostSig), "HOST_FINGERPRINT "+a.hostFP, "PHONE_FINGERPRINT "+phoneFP, "POLICY owner-workstation", "PROOF_PROTOCOL ZOWNER/1", "END") != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	live := &liveSession{phoneFP: phoneFP, phoneDER: append([]byte(nil), phoneDER...), req: make(chan proofRequest, 8), userPresent: initialPresence}
	a.sessionUp(live)
	defer a.sessionDown(phoneFP)
	for {
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "POLL") || line == "PING" {
			present := true
			if strings.HasPrefix(line, "POLL") {
				parts := strings.Fields(line)
				if len(parts) > 1 && strings.EqualFold(parts[1], "LOCKED") {
					present = false
				}
			}
			a.sessionTouch(phoneFP, present)
			var pr *proofRequest
			select {
			case q := <-live.req:
				pr = &q
			default:
			}
			if pr == nil {
				if writeLines(c, "PONG") != nil {
					return
				}
				continue
			}
			issued := time.Now().Unix()
			ttl := pr.ttl
			if ttl < 5 {
				ttl = 5
			}
			if ttl > 120 {
				ttl = 120
			}
			expires := issued + int64(ttl)
			nonce := randomHex(32)
			ah := hex.EncodeToString([]byte(pr.action))
			rh := hex.EncodeToString([]byte(pr.resource))
			if writeLines(c, "PROOF_REQUEST", "ACTION_HEX "+ah, "RESOURCE_HEX "+rh, "NONCE "+nonce, "ISSUED "+strconv.FormatInt(issued, 10), "EXPIRES "+strconv.FormatInt(expires, 10), "END") != nil {
				pr.result <- proofResult{err: errors.New("phone connection lost")}
				return
			}
			rf, err := readFrame(r)
			if err != nil {
				pr.result <- proofResult{err: err}
				return
			}
			if rf["PROOF_RESULT"] != "OK" || rf["SIGNATURE"] == "" {
				pr.result <- proofResult{err: fmt.Errorf("phone proof denied: %s", rf["REASON"])}
				_ = writeLines(c, "PONG")
				continue
			}
			p := OwnerProof{Version: "ZOWNER/1", Action: pr.action, Resource: pr.resource, HostFingerprint: a.hostFP, PhoneFingerprint: phoneFP, PhonePublicKeyDERHex: phonePubHex, Nonce: nonce, Issued: issued, Expires: expires, SignatureDERHex: rf["SIGNATURE"]}
			if err := verifyOwnerProof(p, phoneDER); err != nil {
				pr.result <- proofResult{err: err}
			} else {
				pr.result <- proofResult{proof: p}
			}
			if writeLines(c, "PONG") != nil {
				return
			}
		} else if line == "BYE" {
			return
		} else {
			_ = writeLines(c, "ERR fixed-protocol-only")
		}
	}
}

func (a *Agent) sessionUp(live *liveSession) {
	a.mu.Lock()
	wasEmpty := len(a.sessions) == 0
	now := time.Now()
	a.live[live.phoneFP] = live
	a.sessions[live.phoneFP] = Session{Trusted: true, HostFingerprint: a.hostFP, PhoneFingerprint: live.phoneFP, Since: now, LastSeen: now, Policy: "owner-workstation", HostIdentityProvider: a.identity.Provider(), UserPresent: live.userPresent}
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
	a.mu.Unlock()
	fmt.Printf("TRUSTED session UP phone=%s\n", live.phoneFP)
	// The red pulse is emitted only after mutual cryptographic authentication succeeds.
	a.pulseOwnerVisual()
	if wasEmpty {
		runHook(a.onTrust)
	}
}
func (a *Agent) sessionTouch(phoneFP string, userPresent bool) {
	a.mu.Lock()
	if l := a.live[phoneFP]; l != nil {
		l.userPresent = userPresent
	}
	s := a.sessions[phoneFP]
	s.LastSeen = time.Now()
	s.UserPresent = userPresent
	a.sessions[phoneFP] = s
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
	a.mu.Unlock()
}
func (a *Agent) sessionDown(phoneFP string) {
	a.mu.Lock()
	delete(a.sessions, phoneFP)
	delete(a.live, phoneFP)
	nowEmpty := len(a.sessions) == 0
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
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
func (a *Agent) writeOwnerModeLocked() {
	p := filepath.Join(a.stateDir, "owner-mode.json")
	if len(a.sessions) == 0 {
		_ = os.Remove(p)
		return
	}
	var newest Session
	for _, s := range a.sessions {
		if !s.UserPresent {
			continue
		}
		if newest.Since.IsZero() || s.LastSeen.After(newest.LastSeen) {
			newest = s
		}
	}
	if newest.Since.IsZero() {
		_ = os.Remove(p)
		return
	}
	m := map[string]any{"trusted": true, "user_present": true, "policy": "owner-workstation", "host_fingerprint": a.hostFP, "phone_fingerprint": newest.PhoneFingerprint, "identity_provider": a.identity.Provider(), "since": newest.Since, "last_seen": newest.LastSeen, "control": "local-authenticated"}
	b, _ := json.MarshalIndent(m, "", "  ")
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
func (a *Agent) hasLiveSession() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions) > 0
}

func (a *Agent) startTrustService(serial string, pulse bool) error {
	args := []string{"-s", serial, "shell", "am", "start-foreground-service", "-n", androidPkg + "/" + androidSvc, "--ez", "dev.zorin.trust.ensure", "true"}
	if pulse {
		args = append(args, "--ez", "dev.zorin.trust.pulse", "true")
	}
	out, err := exec.Command("adb", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("TrustService start failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Agent) wakeAndroid(serial string, visible bool) {
	// Known hosts no longer wake the Activity. The foreground TrustService owns the
	// persistent runtime and survives UI removal from Recents.
	if err := a.startTrustService(serial, false); err != nil {
		fmt.Fprintln(os.Stderr, "trust service:", err)
	}
	if visible {
		args := []string{"-s", serial, "shell", "am", "start", "-n", androidPkg + "/" + androidAct, "--ez", "dev.zorin.trust.autoconnect", "true"}
		_ = exec.Command("adb", args...).Run()
	}
	a.mu.Lock()
	a.lastWake[serial] = time.Now()
	a.mu.Unlock()
}

func (a *Agent) pulseOwnerVisual() {
	a.mu.Lock()
	serial := strings.TrimSpace(a.adbSerial)
	if serial == "" {
		for s := range a.seenADB {
			if serial != "" { // Ambiguous: never pulse the wrong device.
				serial = ""
				break
			}
			serial = s
		}
	}
	a.mu.Unlock()
	if serial == "" {
		return
	}
	go func() {
		if err := a.startTrustService(serial, true); err != nil {
			fmt.Fprintln(os.Stderr, "trust visual:", err)
		}
	}()
}

func (a *Agent) shouldHeadlessWake(serial string, first bool) bool {
	if a.pairOnce {
		return false
	}
	if first {
		return true
	}
	if a.hasLiveSession() {
		return false
	}
	a.mu.Lock()
	last := a.lastWake[serial]
	a.mu.Unlock()
	// A successful am start can still be followed by an app-side crash. Never hammer
	// the package in a tight loop; a reconnect is immediate, in-session recovery is bounded.
	return time.Since(last) >= 30*time.Second
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
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "device" {
			continue
		}
		serial := f[0]
		if a.adbSerial != "" && serial != a.adbSerial {
			continue
		}
		current[serial] = true
		_ = exec.Command("adb", "-s", serial, "reverse", "tcp:47472", "tcp:47472").Run()
		a.mu.Lock()
		first := !a.seenADB[serial]
		a.seenADB[serial] = true
		a.mu.Unlock()
		if first {
			fmt.Printf("ADB device connected: %s; reverse installed\n", serial)
		}
		if a.pairOnce && first {
			a.wakeAndroid(serial, true)
		} else if a.shouldHeadlessWake(serial, first) {
			a.wakeAndroid(serial, false)
		}
	}
	a.mu.Lock()
	for s := range a.seenADB {
		if !current[s] {
			delete(a.seenADB, s)
			delete(a.lastWake, s)
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
