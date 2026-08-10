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
	version      = "0.6.0"
	listenAddr   = "127.0.0.1:47472"
	controlAddr  = "127.0.0.1:47473"
	androidPkg   = "dev.zorin.trustruntime"
	androidAct   = "android.app.NativeActivity"
	androidSvc   = "dev.zorin.trustruntime.TrustService"
	protocolName = "ZTRUST/2"
)

type Config struct {
	PairedPhones map[string]string `json:"paired_phones"`
	DeviceLabels map[string]string `json:"device_labels,omitempty"`
	ADBPath      string            `json:"adb_path,omitempty"`
}

type DaemonHealth struct {
	Updated          time.Time `json:"updated"`
	ADBPath          string    `json:"adb_path,omitempty"`
	ADBAvailable     bool      `json:"adb_available"`
	Devices          []string  `json:"devices,omitempty"`
	ReverseOK        []string  `json:"reverse_ok,omitempty"`
	LastServiceStart string    `json:"last_service_start,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

type EventRecord struct {
	Time        time.Time `json:"time"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail,omitempty"`
	Phone       string    `json:"phone_fingerprint,omitempty"`
	UserPresent *bool     `json:"user_present,omitempty"`
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
	action    string
	resource  string
	ttl       int
	requestID string
	prompt    string
	explicit  bool
	result    chan proofResult
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
	onPresence   string
	onAbsence    string
	adbSerial    string
	adbPath      string
	controlToken string

	mu           sync.Mutex
	eventMu      sync.Mutex
	sessions     map[string]Session
	live         map[string]*liveSession
	seenADB      map[string]bool
	lastWake     map[string]time.Time
	lastPresence map[string]bool
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
	a.writeHostInfo()

	switch cmd {
	case "daemon":
		fs := flag.NewFlagSet("daemon", flag.ExitOnError)
		pairOnce := fs.Bool("pair-once", false, "allow the next cryptographically valid, phone-approved device to pair")
		onTrust := fs.String("on-trust", "", "optional local command to run when the first trusted USB session appears")
		onUntrust := fs.String("on-untrust", "", "optional local command to run when the last trusted USB session disappears")
		onPresence := fs.String("on-presence", "", "optional local command when owner presence becomes available")
		onAbsence := fs.String("on-absence", "", "optional local command when owner presence becomes unavailable")
		noADB := fs.Bool("no-adb-watch", false, "listen only; do not configure adb reverse or wake the Android app")
		serial := fs.String("serial", "", "limit ADB watcher to one device serial (adb -s <serial>)")
		adbPath := fs.String("adb", "", "absolute path to adb executable; persisted for autostart reliability")
		_ = fs.Parse(args)
		a.pairOnce = *pairOnce
		a.onTrust = *onTrust
		a.onUntrust = *onUntrust
		a.onPresence = *onPresence
		a.onAbsence = *onAbsence
		a.adbSerial = strings.TrimSpace(*serial)
		if err := a.configureADB(strings.TrimSpace(*adbPath)); err != nil {
			fmt.Fprintf(os.Stderr, "ADB unavailable: %v\n", err)
		}
		fmt.Printf("Zorin Host Agent %s\n", version)
		fmt.Printf("Host identity: %s\n", a.hostFP)
		fmt.Printf("Identity provider: %s\n", a.identity.Provider())
		fmt.Printf("Trust listen: %s\nControl API: %s\n", listenAddr, controlAddr)
		if a.adbPath != "" {
			fmt.Printf("ADB executable: %s\n", a.adbPath)
		} else {
			fmt.Println("ADB executable: NOT FOUND")
		}
		if a.adbSerial != "" {
			fmt.Printf("ADB target: %s\n", a.adbSerial)
		}
		if a.pairOnce {
			fmt.Println("PAIR WINDOW: the next phone approved on-device may be enrolled")
			fmt.Printf("PAIR VERIFICATION: %s\n", pairCodeFromFingerprint(a.hostFP))
			a.recordEvent("pair-window", "info", "Pairing window opened", "Compare the verification code on Windows and the phone before approving.", "", nil)
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
		_ = a.configureADB("")
		a.printStatus()
	case "ui-state":
		a.printUIState()
	case "doctor":
		_ = a.configureADB("")
		a.printDoctor()
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
	case "device":
		runDeviceCLI(a, args)
	case "unpair-all":
		a.cfg.PairedPhones = map[string]string{}
		a.cfg.DeviceLabels = map[string]string{}
		if err := a.saveConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("All paired phones removed.")
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s [daemon|status|ui-state|doctor|authorize|credential|gate|policy|identity|device|fingerprint|unpair-all|version] [options]\n", filepath.Base(os.Args[0]))
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
	cfg := Config{PairedPhones: map[string]string{}, DeviceLabels: map[string]string{}}
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
		if cfg.PairedPhones == nil {
			cfg.PairedPhones = map[string]string{}
		}
		if cfg.DeviceLabels == nil {
			cfg.DeviceLabels = map[string]string{}
		}
	}
	token, err := ensureControlToken(stateDir)
	if err != nil {
		return nil, err
	}
	_, _ = ensurePolicy(stateDir)
	return &Agent{identity: id, hostPub: pub, hostFP: id.Fingerprint(), cfg: cfg, cfgPath: cfgPath, stateDir: stateDir, adbPath: strings.TrimSpace(cfg.ADBPath), controlToken: token, sessions: map[string]Session{}, live: map[string]*liveSession{}, seenADB: map[string]bool{}, lastWake: map[string]time.Time{}, lastPresence: map[string]bool{}}, nil
}

func (a *Agent) configureADB(explicit string) error {
	candidates := []string{}
	if strings.TrimSpace(explicit) != "" {
		candidates = append(candidates, strings.TrimSpace(explicit))
	}
	if strings.TrimSpace(a.adbPath) != "" {
		candidates = append(candidates, strings.TrimSpace(a.adbPath))
	}
	if strings.TrimSpace(a.cfg.ADBPath) != "" {
		candidates = append(candidates, strings.TrimSpace(a.cfg.ADBPath))
	}
	if p, err := exec.LookPath("adb"); err == nil {
		candidates = append(candidates, p)
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		abs, err := filepath.Abs(c)
		if err == nil {
			c = abs
		}
		st, err := os.Stat(c)
		if err != nil || st.IsDir() {
			continue
		}
		a.adbPath = c
		if a.cfg.ADBPath != c {
			a.cfg.ADBPath = c
			_ = a.saveConfig()
		}
		return nil
	}
	a.adbPath = ""
	if strings.TrimSpace(explicit) != "" {
		return fmt.Errorf("configured adb does not exist: %s", explicit)
	}
	return errors.New("adb executable not found; reinstall autostart from a shell where adb is available")
}

func (a *Agent) adbCommand(args ...string) (*exec.Cmd, error) {
	if strings.TrimSpace(a.adbPath) == "" {
		if err := a.configureADB(""); err != nil {
			return nil, err
		}
	}
	return exec.Command(a.adbPath, args...), nil
}

func pairCodeFromFingerprint(fp string) string {
	words := []string{"EMBER", "FALCON", "NOVA", "WOLF", "ORBIT", "ONYX", "PIXEL", "RAVEN", "SOLAR", "TITAN", "VECTOR", "COMET", "PULSE", "ATLAS", "NEXUS", "VAULT"}
	hexOnly := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f') {
			return r
		}
		return -1
	}, fp)
	if len(hexOnly) < 8 {
		return "UNAVAILABLE"
	}
	b, err := hex.DecodeString(hexOnly[:8])
	if err != nil || len(b) < 4 {
		return "UNAVAILABLE"
	}
	return fmt.Sprintf("%s-%s %02d", words[int(b[0])&15], words[int(b[1])&15], (int(b[2])<<8|int(b[3]))%100)
}

func (a *Agent) recordEvent(kind, severity, title, detail, phone string, present *bool) {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	e := EventRecord{Time: time.Now(), Type: kind, Severity: severity, Title: title, Detail: detail, Phone: phone, UserPresent: present}
	b, _ := json.Marshal(e)
	p := filepath.Join(a.stateDir, "events.jsonl")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	// Bound the timeline file to ~512 KiB so a long-running workstation never grows it forever.
	if st, err := os.Stat(p); err == nil && st.Size() > 512*1024 {
		if data, err := os.ReadFile(p); err == nil {
			start := len(data) / 2
			if i := strings.IndexByte(string(data[start:]), '\n'); i >= 0 {
				start += i + 1
			}
			_ = os.WriteFile(p, data[start:], 0600)
		}
	}
}

func (a *Agent) writeHostInfo() {
	m := map[string]any{"version": version, "host_fingerprint": a.hostFP, "identity_provider": a.identity.Provider(), "protocol": protocolName, "pair_verification": pairCodeFromFingerprint(a.hostFP)}
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(a.stateDir, "host-info.json"), b, 0600)
}

func (a *Agent) writeDaemonHealth(h DaemonHealth) {
	h.Updated = time.Now()
	b, _ := json.MarshalIndent(h, "", "  ")
	_ = os.WriteFile(filepath.Join(a.stateDir, "daemon-health.json"), b, 0600)
	a.mu.Lock()
	a.writeUIStateLocked(&h)
	a.mu.Unlock()
}

func (a *Agent) printDoctor() {
	fmt.Println("Zorin Host Agent doctor")
	if a.adbPath == "" {
		fmt.Println("ADB: NOT FOUND")
		return
	}
	fmt.Printf("ADB: %s\n", a.adbPath)
	cmd, err := a.adbCommand("devices")
	if err != nil {
		fmt.Println("adb devices:", err)
		return
	}
	out, err := cmd.CombinedOutput()
	fmt.Printf("adb devices:\n%s", string(out))
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "device" {
			continue
		}
		serial := f[0]
		if a.adbSerial != "" && serial != a.adbSerial {
			continue
		}
		fmt.Printf("\n[%s]\n", serial)
		if c, e := a.adbCommand("-s", serial, "reverse", "--list"); e == nil {
			o, er := c.CombinedOutput()
			fmt.Printf("reverse --list: %s", string(o))
			if er != nil {
				fmt.Printf("ERROR %v\n", er)
			}
		}
		if c, e := a.adbCommand("-s", serial, "shell", "pidof", androidPkg); e == nil {
			o, er := c.CombinedOutput()
			fmt.Printf("runtime pid: %s", string(o))
			if er != nil {
				fmt.Printf("not running (%v)\n", er)
			}
		}
		if c, e := a.adbCommand("-s", serial, "shell", "dumpsys", "activity", "services", androidPkg); e == nil {
			o, _ := c.CombinedOutput()
			text := string(o)
			if strings.Contains(text, "TrustService") {
				fmt.Println("TrustService: PRESENT in ActivityManager")
			} else {
				fmt.Println("TrustService: NOT PRESENT in ActivityManager")
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(a.stateDir, "daemon-health.json")); err == nil {
		fmt.Printf("\nLast daemon health:\n%s\n", b)
	}
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

type UIState struct {
	Version          string    `json:"version"`
	Updated          time.Time `json:"updated"`
	DeviceTrusted    bool      `json:"device_trusted"`
	OwnerPresent     bool      `json:"owner_present"`
	AuthorityEnabled bool      `json:"authority_enabled"`
	TransportOnline  bool      `json:"transport_online"`
	Transport        string    `json:"transport"`
	HostFingerprint  string    `json:"host_fingerprint"`
	IdentityProvider string    `json:"identity_provider"`
	PhoneFingerprint string    `json:"phone_fingerprint,omitempty"`
	PhoneLabel       string    `json:"phone_label,omitempty"`
	PairVerification string    `json:"pair_verification"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
}

func (a *Agent) anyPresentLocked() bool {
	for _, s := range a.sessions {
		if s.Trusted && s.UserPresent {
			return true
		}
	}
	return false
}

func (a *Agent) writeUIStateLocked(health *DaemonHealth) {
	st := UIState{Version: version, Updated: time.Now(), HostFingerprint: a.hostFP, IdentityProvider: a.identity.Provider(), PairVerification: pairCodeFromFingerprint(a.hostFP), Transport: "Offline"}
	var newest Session
	for _, s := range a.sessions {
		if s.Trusted {
			st.DeviceTrusted = true
		}
		if s.UserPresent {
			st.OwnerPresent = true
		}
		if newest.LastSeen.IsZero() || s.LastSeen.After(newest.LastSeen) {
			newest = s
		}
	}
	st.AuthorityEnabled = st.DeviceTrusted && st.OwnerPresent
	if !newest.LastSeen.IsZero() {
		st.PhoneFingerprint = newest.PhoneFingerprint
		st.LastSeen = newest.LastSeen
		st.PhoneLabel = a.cfg.DeviceLabels[newest.PhoneFingerprint]
		if st.PhoneLabel == "" {
			st.PhoneLabel = "Owner phone"
		}
	}
	var h DaemonHealth
	if health != nil {
		h = *health
	} else if raw, err := os.ReadFile(filepath.Join(a.stateDir, "daemon-health.json")); err == nil {
		_ = json.Unmarshal(raw, &h)
	}
	if !h.Updated.IsZero() && time.Since(h.Updated) < 8*time.Second {
		if len(h.Devices) > 0 && len(h.ReverseOK) > 0 {
			st.TransportOnline = true
			st.Transport = "USB"
		} else if h.ADBAvailable {
			st.Transport = "Recovering"
		}
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(filepath.Join(a.stateDir, "ui-state.json"), b, 0600)
}

func (a *Agent) printUIState() {
	a.mu.Lock()
	a.writeUIStateLocked(nil)
	a.mu.Unlock()
	if b, err := os.ReadFile(filepath.Join(a.stateDir, "ui-state.json")); err == nil {
		fmt.Println(string(b))
		return
	}
	fmt.Println(`{"device_trusted":false,"owner_present":false,"authority_enabled":false,"transport_online":false,"transport":"Offline"}`)
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

	trusted, present := false, false
	var sessions []Session
	if raw, err := os.ReadFile(filepath.Join(a.stateDir, "session.json")); err == nil {
		_ = json.Unmarshal(raw, &sessions)
		for _, ss := range sessions {
			if ss.Trusted {
				trusted = true
			}
			if ss.UserPresent {
				present = true
			}
		}
	}
	var health DaemonHealth
	healthFresh := false
	if raw, err := os.ReadFile(filepath.Join(a.stateDir, "daemon-health.json")); err == nil {
		if json.Unmarshal(raw, &health) == nil && !health.Updated.IsZero() {
			healthFresh = time.Since(health.Updated) < 8*time.Second
		}
	}
	transport := healthFresh && len(health.Devices) > 0 && len(health.ReverseOK) > 0
	transportText := "OFFLINE"
	if transport {
		transportText = "USB / ADB"
	} else if healthFresh && health.ADBAvailable {
		transportText = "RECOVERING"
	}
	presenceText := "ABSENT"
	if trusted {
		if present {
			presenceText = "PRESENT"
		} else {
			presenceText = "LOCKED"
		}
	}
	authorityText := "SUSPENDED"
	if trusted && present {
		authorityText = "ENABLED"
	}
	trustText := "INACTIVE"
	if trusted {
		trustText = "ACTIVE"
	}
	fmt.Println("\nTrust Center state:")
	fmt.Printf("  Device trust:   %s\n", trustText)
	fmt.Printf("  Owner presence: %s\n", presenceText)
	fmt.Printf("  Owner actions:  %s\n", authorityText)
	fmt.Printf("  Transport:      %s\n", transportText)
	fmt.Printf("  Pair code:      %s\n", pairCodeFromFingerprint(a.hostFP))

	fmt.Printf("\nPolicy: %s\n", filepath.Join(a.stateDir, "policy.json"))
	fmt.Printf("Control API: %s (token file protected in state dir)\n", controlAddr)
	if a.adbPath != "" {
		fmt.Printf("ADB executable: %s\n", a.adbPath)
	} else {
		fmt.Println("ADB executable: NOT FOUND")
	}
	if len(sessions) > 0 {
		b, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Printf("Active state:\n%s\n", b)
	} else {
		fmt.Println("Active state: none")
	}
	if b, err := os.ReadFile(filepath.Join(a.stateDir, "owner-mode.json")); err == nil {
		fmt.Printf("Owner authority:\n%s\n", b)
	} else if trusted {
		fmt.Println("Owner authority: SUSPENDED (phone locked)")
	} else {
		fmt.Println("Owner authority: INACTIVE")
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
		if a.cfg.DeviceLabels == nil {
			a.cfg.DeviceLabels = map[string]string{}
		}
		if a.cfg.DeviceLabels[phoneFP] == "" {
			a.cfg.DeviceLabels[phoneFP] = "Owner phone"
		}
		a.pairOnce = false
		_ = a.saveConfig()
		paired = true
		fmt.Printf("PAIRED phone %s\n", phoneFP)
		a.recordEvent("paired", "success", "Phone paired", "Owner workstation enrollment completed.", phoneFP, nil)
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
			ph := hex.EncodeToString([]byte(pr.prompt))
			mode := "PRESENCE"
			if pr.explicit {
				mode = "EXPLICIT"
			}
			requestID := sanitize(pr.requestID)
			if requestID == "" {
				requestID = randomHex(16)
			}
			if writeLines(c, "PROOF_REQUEST", "REQUEST_ID "+requestID, "MODE "+mode, "PROMPT_HEX "+ph, "ACTION_HEX "+ah, "RESOURCE_HEX "+rh, "NONCE "+nonce, "ISSUED "+strconv.FormatInt(issued, 10), "EXPIRES "+strconv.FormatInt(expires, 10), "END") != nil {
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
	wasPresent := a.anyPresentLocked()
	now := time.Now()
	a.live[live.phoneFP] = live
	a.sessions[live.phoneFP] = Session{Trusted: true, HostFingerprint: a.hostFP, PhoneFingerprint: live.phoneFP, Since: now, LastSeen: now, Policy: "owner-workstation", HostIdentityProvider: a.identity.Provider(), UserPresent: live.userPresent}
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
	a.writeUIStateLocked(nil)
	nowPresent := a.anyPresentLocked()
	a.mu.Unlock()
	fmt.Printf("TRUSTED session UP phone=%s\n", live.phoneFP)
	p := live.userPresent
	a.recordEvent("device-trust", "success", "Device trust established", "Mutual ZTRUST/2 authentication succeeded.", live.phoneFP, &p)
	// The red pulse is emitted only after mutual cryptographic authentication succeeds.
	a.pulseOwnerVisual()
	if wasEmpty {
		runHook(a.onTrust)
	}
	if !wasPresent && nowPresent {
		runHook(a.onPresence)
	}
}
func (a *Agent) sessionTouch(phoneFP string, userPresent bool) {
	a.mu.Lock()
	wasPresent := a.anyPresentLocked()
	if a.lastPresence == nil {
		a.lastPresence = map[string]bool{}
	}
	old, hadOld := a.lastPresence[phoneFP]
	a.lastPresence[phoneFP] = userPresent
	if l := a.live[phoneFP]; l != nil {
		l.userPresent = userPresent
	}
	s := a.sessions[phoneFP]
	s.LastSeen = time.Now()
	s.UserPresent = userPresent
	a.sessions[phoneFP] = s
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
	a.writeUIStateLocked(nil)
	nowPresent := a.anyPresentLocked()
	a.mu.Unlock()
	if !hadOld || old != userPresent {
		p := userPresent
		if userPresent {
			a.recordEvent("owner-presence", "success", "Owner presence restored", "Phone unlocked; owner-authorized actions are enabled.", phoneFP, &p)
		} else {
			a.recordEvent("owner-presence", "info", "Owner authority suspended", "Phone locked; device trust remains active, owner proofs are denied.", phoneFP, &p)
		}
	}
	if !wasPresent && nowPresent {
		runHook(a.onPresence)
	}
	if wasPresent && !nowPresent {
		runHook(a.onAbsence)
	}
}
func (a *Agent) sessionDown(phoneFP string) {
	a.mu.Lock()
	wasPresent := a.anyPresentLocked()
	delete(a.sessions, phoneFP)
	delete(a.live, phoneFP)
	delete(a.lastPresence, phoneFP)
	nowEmpty := len(a.sessions) == 0
	nowPresent := a.anyPresentLocked()
	a.writeSessionLocked()
	a.writeOwnerModeLocked()
	a.writeUIStateLocked(nil)
	a.mu.Unlock()
	fmt.Printf("TRUSTED session DOWN phone=%s\n", phoneFP)
	a.recordEvent("device-trust-lost", "info", "Device trust ended", "Authenticated transport session ended.", phoneFP, nil)
	if wasPresent && !nowPresent {
		runHook(a.onAbsence)
	}
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

func runDeviceCLI(a *Agent, args []string) {
	if len(args) == 0 || args[0] == "list" {
		fps := make([]string, 0, len(a.cfg.PairedPhones))
		for fp := range a.cfg.PairedPhones {
			fps = append(fps, fp)
		}
		sort.Strings(fps)
		for _, fp := range fps {
			label := a.cfg.DeviceLabels[fp]
			if label == "" {
				label = "Owner phone"
			}
			fmt.Printf("%s\t%s\n", fp, label)
		}
		return
	}
	fs := flag.NewFlagSet("device "+args[0], flag.ExitOnError)
	fp := fs.String("fingerprint", "", "paired phone fingerprint")
	name := fs.String("name", "", "friendly device name")
	_ = fs.Parse(args[1:])
	key := strings.TrimSpace(*fp)
	if key == "" {
		fatal(errors.New("--fingerprint is required"))
	}
	if _, ok := a.cfg.PairedPhones[key]; !ok {
		fatal(errors.New("device is not paired"))
	}
	switch args[0] {
	case "rename":
		n := strings.TrimSpace(*name)
		if n == "" {
			fatal(errors.New("--name is required"))
		}
		if a.cfg.DeviceLabels == nil {
			a.cfg.DeviceLabels = map[string]string{}
		}
		a.cfg.DeviceLabels[key] = n
		if err := a.saveConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("Renamed device to", n)
	case "revoke":
		delete(a.cfg.PairedPhones, key)
		delete(a.cfg.DeviceLabels, key)
		if err := a.saveConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("Revoked device", key)
	default:
		fatal(errors.New("usage: device [list|rename|revoke]"))
	}
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
	cmd, e := a.adbCommand(args...)
	if e != nil {
		return e
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("TrustService start failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Agent) wakeAndroid(serial string, visible bool) error {
	// Known hosts no longer wake the Activity. The foreground TrustService owns the
	// persistent runtime and survives UI removal from Recents.
	var startErr error
	if err := a.startTrustService(serial, false); err != nil {
		startErr = err
		fmt.Fprintln(os.Stderr, "trust service:", err)
	}
	if visible {
		args := []string{"-s", serial, "shell", "am", "start", "-n", androidPkg + "/" + androidAct, "--ez", "dev.zorin.trust.autoconnect", "true"}
		if cmd, e := a.adbCommand(args...); e == nil {
			_ = cmd.Run()
		}
	}
	a.mu.Lock()
	a.lastWake[serial] = time.Now()
	a.mu.Unlock()
	return startErr
}

func (a *Agent) pulseOwnerVisual() {
	a.mu.Lock()
	serial := strings.TrimSpace(a.adbSerial)
	if serial == "" {
		for s := range a.seenADB {
			if serial != "" {
				serial = ""
				break
			} // ambiguous: never pulse the wrong device
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
	h := DaemonHealth{ADBPath: a.adbPath}
	if err := a.configureADB(""); err != nil {
		h.ADBAvailable = false
		h.LastError = err.Error()
		a.writeDaemonHealth(h)
		return
	}
	h.ADBPath = a.adbPath
	h.ADBAvailable = true
	cmd, e := a.adbCommand("devices")
	if e != nil {
		h.LastError = e.Error()
		a.writeDaemonHealth(h)
		return
	}
	out, err := cmd.Output()
	if err != nil {
		h.LastError = "adb devices: " + err.Error()
		a.writeDaemonHealth(h)
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
		h.Devices = append(h.Devices, serial)
		rc, ce := a.adbCommand("-s", serial, "reverse", "tcp:47472", "tcp:47472")
		reverseOK := false
		if ce == nil {
			if o, er := rc.CombinedOutput(); er == nil {
				reverseOK = true
				h.ReverseOK = append(h.ReverseOK, serial)
			} else {
				h.LastError = fmt.Sprintf("adb reverse %s: %v (%s)", serial, er, strings.TrimSpace(string(o)))
			}
		}
		a.mu.Lock()
		first := !a.seenADB[serial]
		a.seenADB[serial] = true
		a.mu.Unlock()
		if first {
			fmt.Printf("ADB device connected: %s; reverse=%v\n", serial, reverseOK)
			a.recordEvent("transport-up", "info", "USB transport detected", fmt.Sprintf("ADB device %s; reverse=%v", serial, reverseOK), "", nil)
		}
		wake := false
		visible := false
		if a.pairOnce && first {
			wake = true
			visible = true
		} else if a.shouldHeadlessWake(serial, first) {
			wake = true
		}
		if wake {
			err := a.wakeAndroid(serial, visible)
			h.LastServiceStart = time.Now().Format(time.RFC3339)
			if err != nil {
				h.LastError = err.Error()
			}
		}
	}
	a.mu.Lock()
	for s := range a.seenADB {
		if !current[s] {
			delete(a.seenADB, s)
			delete(a.lastWake, s)
			fmt.Printf("ADB device disconnected: %s\n", s)
			a.recordEvent("transport-down", "info", "USB transport lost", "ADB device disconnected; trust will require a fresh authenticated session on recovery.", "", nil)
		}
	}
	a.mu.Unlock()
	a.writeDaemonHealth(h)
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
