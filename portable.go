package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPortableTrustAddr     = "0.0.0.0:47482"
	defaultPortableBootstrapAddr = "0.0.0.0:47476"
)

func runPortable(args []string) error {
	fs := flag.NewFlagSet("portable", flag.ContinueOnError)
	trustAddr := fs.String("listen", defaultPortableTrustAddr, "direct ZTRUST listener")
	bootstrapAddr := fs.String("bootstrap", defaultPortableBootstrapAddr, "temporary bootstrap HTTP listener")
	ttl := fs.Duration("ttl", 15*time.Minute, "maximum lifetime of the direct transport invitation")
	proofOut := fs.String("proof-out", "", "write an explicit short-lived owner proof after trust is established")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *ttl < time.Minute || *ttl > time.Hour {
		return errors.New("portable --ttl must be between 1m and 1h")
	}

	identity, err := newEphemeralIdentity()
	if err != nil {
		return fmt.Errorf("create ephemeral host identity: %w", err)
	}

	stateDir, err := os.MkdirTemp("", "zorin-trust-portable-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDir)

	controlToken := randomHex(32)
	invite := randomHex(16)
	expires := time.Now().Add(*ttl)
	agent := &Agent{
		identity:        identity,
		hostPub:         identity.PublicDER(),
		hostFP:          identity.Fingerprint(),
		cfg:             Config{PairedPhones: map[string]string{}, DeviceLabels: map[string]string{}},
		cfgPath:         filepath.Join(stateDir, "config.json"),
		stateDir:        stateDir,
		pairOnce:        true,
		controlToken:    controlToken,
		listenAddr:      strings.TrimSpace(*trustAddr),
		controlAddr:     "127.0.0.1:0",
		portable:        true,
		portableInvite:  invite,
		portableExpires: expires,
		persistState:    false,
		sessions:        map[string]Session{},
		live:            map[string]*liveSession{},
		seenADB:         map[string]bool{},
		lastWake:        map[string]time.Time{},
		lastPresence:    map[string]bool{},
	}

	if agent.listenAddr == "" {
		return errors.New("portable trust listener cannot be empty")
	}

	_, trustPortText, err := net.SplitHostPort(agent.listenAddr)
	if err != nil {
		return fmt.Errorf("invalid portable --listen: %w", err)
	}
	trustPort, err := strconv.Atoi(trustPortText)
	if err != nil || trustPort < 1 || trustPort > 65535 {
		return errors.New("portable trust port is invalid")
	}

	bootstrap, err := startPortableBootstrap(
		agent,
		strings.TrimSpace(*bootstrapAddr),
		trustPort,
		expires,
		invite,
	)
	if err != nil {
		return err
	}
	defer bootstrap.Close()

	fmt.Printf("Zorin Trust Portable %s\n", version)
	fmt.Println("Mode: ephemeral direct-LAN owner session")
	fmt.Printf("Host identity: %s\n", agent.hostFP)
	fmt.Printf("Pair verification: %s\n", pairCodeFromFingerprint(agent.hostFP))
	fmt.Printf("Trust listen: %s\n", agent.listenAddr)
	fmt.Printf("Invitation expires: %s\n", expires.Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Open one of these addresses on the phone while both devices are on the same LAN:")
	for _, address := range portableBootstrapURLs(strings.TrimSpace(*bootstrapAddr), invite) {
		fmt.Printf("  %s\n", address)
	}
	fmt.Println()
	fmt.Println("Then tap OPEN ZORIN TRUST and verify the pairing code before approving the temporary workstation.")
	fmt.Println("Nothing is installed on this computer; the host key and paired-phone state disappear when this process exits.")
	if strings.TrimSpace(*proofOut) != "" {
		fmt.Printf("Owner proof output: %s\n", *proofOut)
		fmt.Println("After trust is established, the phone will ask for one explicit approval to issue that proof.")
		go agent.writePortableOwnerProofWhenTrusted(*proofOut)
	}
	fmt.Println()

	return agent.serve()
}

func (a *Agent) writePortableOwnerProofWhenTrusted(outputPath string) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return
	}

	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		status := a.controlStatus()
		if status.Trusted {
			resource := "host:" + a.hostFP
			resp := a.authorizeDetailed(
				"portable.session",
				resource,
				"Разрешить временной рабочей станции получить короткоживущий owner proof?",
				"",
				true,
			)
			if !resp.Allowed || resp.Proof == nil {
				fmt.Fprintf(os.Stderr, "Portable owner proof not issued: %s\n", portableProofFailure(resp))
				return
			}

			raw, err := json.MarshalIndent(resp.Proof, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Portable owner proof encode failed: %v\n", err)
				return
			}

			if err := os.WriteFile(outputPath, raw, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "Portable owner proof write failed: %v\n", err)
				return
			}

			fmt.Printf("Portable owner proof written: %s\n", outputPath)
			fmt.Printf("Proof expires: %s\n", time.Unix(resp.Proof.Expires, 0).Format(time.RFC3339))
			return
		}

		time.Sleep(250 * time.Millisecond)
	}

	fmt.Fprintln(os.Stderr, "Portable owner proof was not requested: trusted phone did not connect before timeout")
}

func portableProofFailure(resp controlResponse) string {
	if strings.TrimSpace(resp.Error) != "" {
		return resp.Error
	}
	if strings.TrimSpace(resp.Reason) != "" {
		return resp.Reason
	}
	return "phone approval was not granted"
}

type portableBootstrapServer struct {
	server   *http.Server
	listener net.Listener
}

func (s *portableBootstrapServer) Close() {
	if s == nil {
		return
	}
	_ = s.server.Close()
	_ = s.listener.Close()
}

func startPortableBootstrap(
	agent *Agent,
	addr string,
	trustPort int,
	expires time.Time,
	invite string,
) (*portableBootstrapServer, error) {
	if addr == "" {
		return nil, errors.New("portable bootstrap listener cannot be empty")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("start portable bootstrap listener: %w", err)
	}

	mux := http.NewServeMux()
	bootstrapPath := "/connect/" + invite
	mux.HandleFunc(bootstrapPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != bootstrapPath {
			http.NotFound(w, r)
			return
		}

		host := requestHostIP(r)
		if !isPrivateIPv4(net.ParseIP(host)) {
			http.Error(w, "Open this page through a private IPv4 address of the portable computer.", http.StatusBadRequest)
			return
		}

		deepLink := portableDeepLink(host, trustPort, expires, invite)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintf(
			w,
			portableBootstrapHTML,
			html.EscapeString(pairCodeFromFingerprint(agent.hostFP)),
			html.EscapeString(agent.hostFP),
			html.EscapeString(expires.Format(time.RFC3339)),
			html.EscapeString(deepLink),
		)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		status := agent.controlStatus()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":           version,
			"portable":          true,
			"trusted":           status.Trusted,
			"owner_present":     status.OwnerPresent,
			"host_fingerprint":  agent.hostFP,
			"pair_verification": pairCodeFromFingerprint(agent.hostFP),
			"expires":           expires,
		})
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       10 * time.Second,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return &portableBootstrapServer{
		server:   server,
		listener: listener,
	}, nil
}

func portableDeepLink(host string, port int, expires time.Time, invite string) string {
	values := url.Values{}
	values.Set("host", host)
	values.Set("port", strconv.Itoa(port))
	values.Set("expires", strconv.FormatInt(expires.Unix(), 10))
	values.Set("mode", "portable")
	values.Set("invite", invite)

	return "zorintrust://connect?" + values.Encode()
}

func requestHostIP(r *http.Request) string {
	host := r.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.Trim(host, "[]")
}

func portableBootstrapURLs(addr string, invite string) []string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	addresses := privateInterfaceIPv4()
	out := make([]string, 0, len(addresses))
	for _, ip := range addresses {
		out = append(
			out,
			"http://"+net.JoinHostPort(ip, port)+"/connect/"+invite,
		)
	}
	return out
}

func privateInterfaceIPv4() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}

			if !isPrivateIPv4(ip) {
				continue
			}

			text := ip.To4().String()
			if !seen[text] {
				seen[text] = true
				out = append(out, text)
			}
		}
	}

	sort.Strings(out)
	return out
}

func isPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}

	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	case v4[0] == 169 && v4[1] == 254:
		return true
	default:
		return false
	}
}

const portableBootstrapHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Zorin Trust Portable</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0d10;color:#f5f7fa;margin:0;padding:32px}
main{max-width:680px;margin:0 auto}
.card{background:#141820;border:1px solid #29313d;border-radius:18px;padding:24px;margin:18px 0}
h1{font-size:30px;margin:0 0 8px}.muted{color:#9ba8b7}.code{font-size:28px;font-weight:700;letter-spacing:.04em}
.fp{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.button{display:block;text-align:center;background:#e53935;color:white;text-decoration:none;font-weight:700;padding:16px 20px;border-radius:12px;margin-top:18px}
</style>
</head>
<body>
<main>
<h1>Zorin Trust Portable</h1>
<p class="muted">Temporary direct-LAN owner session. No permanent host identity is installed on this computer.</p>
<div class="card">
<div class="muted">VERIFY THIS CODE</div>
<div class="code">%s</div>
<p class="fp">%s</p>
<p class="muted">Invitation expires %s</p>
<a class="button" href="%s">OPEN ZORIN TRUST</a>
</div>
<p class="muted">Approve only if this code matches the portable computer. The temporary workstation is forgotten when the portable session ends.</p>
</main>
</body>
</html>`
