package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type controlRequest struct {
	Token     string `json:"token"`
	Op        string `json:"op"`
	Action    string `json:"action,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Prompt    string `json:"prompt,omitempty"`
	Explicit  bool   `json:"explicit,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type controlResponse struct {
	OK      bool           `json:"ok"`
	Allowed bool           `json:"allowed,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Proof   *OwnerProof    `json:"proof,omitempty"`
	Status  *controlStatus `json:"status,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type controlStatus struct {
	Trusted          bool   `json:"trusted"`
	OwnerPresent     bool   `json:"owner_present"`
	HostFingerprint  string `json:"host_fingerprint"`
	PhoneFingerprint string `json:"phone_fingerprint,omitempty"`
	IdentityProvider string `json:"identity_provider"`
}

func (a *Agent) serveControl() error {
	ln, err := net.Listen("tcp", a.controlAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go a.handleControl(c)
	}
}

func (a *Agent) handleControl(c net.Conn) {
	defer c.Close()
	// Явное подтверждение на телефоне — намеренно «человеческая» операция.
	// Таймаут оставляем ограниченным, но достаточным для разблокировки и тапа.
	_ = c.SetDeadline(time.Now().Add(75 * time.Second))
	var req controlRequest
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(controlResponse{Error: "malformed request"})
		return
	}
	if req.Token == "" || req.Token != a.controlToken {
		_ = json.NewEncoder(c).Encode(controlResponse{Error: "unauthorized local control client"})
		return
	}
	switch req.Op {
	case "authorize":
		resp := a.authorizeDetailed(req.Action, req.Resource, req.Prompt, req.RequestID, req.Explicit)
		_ = json.NewEncoder(c).Encode(resp)
	case "status":
		status := a.controlStatus()
		reason := "no trusted device session"
		if status.Trusted && status.OwnerPresent {
			reason = "trusted device + owner presence"
		} else if status.Trusted {
			reason = "trusted device; phone locked"
		}
		_ = json.NewEncoder(c).Encode(controlResponse{
			OK:      true,
			Allowed: status.Trusted,
			Reason:  reason,
			Status:  &status,
		})
	default:
		_ = json.NewEncoder(c).Encode(controlResponse{Error: "unsupported control operation"})
	}
}

func (a *Agent) controlStatus() controlStatus {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := controlStatus{
		Trusted:          len(a.live) > 0,
		HostFingerprint:  a.hostFP,
		IdentityProvider: a.identity.Provider(),
	}

	for _, session := range a.live {
		if status.PhoneFingerprint == "" {
			status.PhoneFingerprint = session.phoneFP
		}
		if session.userPresent {
			status.OwnerPresent = true
			status.PhoneFingerprint = session.phoneFP
			break
		}
	}

	return status
}

func (a *Agent) authorize(action, resource string) controlResponse {
	return a.authorizeDetailed(action, resource, "", "", false)
}

func (a *Agent) authorizeDetailed(action, resource, prompt, requestID string, explicit bool) controlResponse {
	action = strings.TrimSpace(action)
	resource = strings.TrimSpace(resource)
	prompt = strings.TrimSpace(prompt)
	requestID = strings.TrimSpace(requestID)
	if action == "" || resource == "" {
		return controlResponse{Error: "action and resource are required"}
	}
	if requestID == "" {
		requestID = randomHex(16)
	}
	if len(prompt) > 360 {
		prompt = prompt[:360]
	}

	a.mu.Lock()
	trusted := len(a.live) > 0
	var live *liveSession
	for _, s := range a.live {
		if s.userPresent {
			live = s
			break
		}
		if live == nil {
			live = s
		}
	}
	present := live != nil && live.userPresent
	a.mu.Unlock()

	cfg := loadPolicy(a.stateDir)
	d := evaluatePolicy(cfg, action, resource, PolicyContext{
		Trusted:      trusted,
		OwnerPresent: present,
	})
	if !d.Allowed {
		a.recordEvent("authority-denied", "warning", "Action denied", action+" -> "+resource+": "+d.Reason, "", nil)
		return controlResponse{OK: true, Allowed: false, Reason: d.Reason}
	}
	if live == nil {
		return controlResponse{OK: true, Allowed: false, Reason: "trusted session disappeared"}
	}

	// Клиент может попросить более строгий режим, но ослабить правило policy
	// он не может. Для чувствительных действий explicit включается здесь.
	explicit = explicit || d.RequireExplicit

	ttl := 30
	if d.Rule != nil && d.Rule.ProofTTLSeconds > 0 {
		ttl = d.Rule.ProofTTLSeconds
	}
	if explicit {
		a.recordEvent("approval-requested", "info", "Approval requested", promptOrAction(prompt, action), live.phoneFP, nil)
		go a.wakeApprovalActivity()
	}
	pr := proofRequest{action: action, resource: resource, ttl: ttl, requestID: requestID, prompt: prompt, explicit: explicit, result: make(chan proofResult, 1)}
	select {
	case live.req <- pr:
	case <-time.After(2 * time.Second):
		return controlResponse{Error: "phone proof queue unavailable"}
	}
	wait := 8 * time.Second
	if explicit {
		wait = 55 * time.Second
	}
	select {
	case r := <-pr.result:
		if r.err != nil {
			sev := "warning"
			if strings.Contains(strings.ToLower(r.err.Error()), "denied") {
				sev = "info"
			}
			a.recordEvent("proof-error", sev, "Approval not granted", r.err.Error(), live.phoneFP, nil)
			return controlResponse{Error: r.err.Error()}
		}
		title := "Owner proof issued"
		if explicit {
			title = "Action approved"
		}
		a.recordEvent("proof-issued", "success", title, action+" -> "+resource, live.phoneFP, nil)
		return controlResponse{OK: true, Allowed: true, Reason: d.Reason, Proof: &r.proof}
	case <-time.After(wait):
		return controlResponse{Error: "phone approval timed out"}
	}
}

func promptOrAction(prompt, action string) string {
	if strings.TrimSpace(prompt) != "" {
		return prompt
	}
	return action
}

func (a *Agent) wakeApprovalActivity() {
	if strings.TrimSpace(a.adbPath) == "" {
		_ = a.configureADB("")
	}
	if strings.TrimSpace(a.adbPath) == "" {
		return
	}
	serials := a.currentADBDevices()
	if len(serials) != 1 {
		return
	}
	cmd, err := a.adbCommand("-s", serials[0], "shell", "am", "start", "-n", androidPkg+"/"+androidAct, "--ez", "dev.zorin.approval", "true")
	if err == nil {
		_ = cmd.Run()
	}
}

func (a *Agent) currentADBDevices() []string {
	cmd, err := a.adbCommand("devices")
	if err != nil {
		return nil
	}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var serials []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "device" {
			if a.adbSerial == "" || a.adbSerial == f[0] {
				serials = append(serials, f[0])
			}
		}
	}
	return serials
}

func requestControl(a *Agent, req controlRequest) (controlResponse, error) {
	req.Token = a.controlToken
	c, err := net.DialTimeout("tcp", a.controlAddr, 2*time.Second)
	if err != nil {
		return controlResponse{}, fmt.Errorf("host agent control API is not running: %w", err)
	}
	defer c.Close()
	timeout := 12 * time.Second
	if req.Explicit {
		timeout = 70 * time.Second
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return controlResponse{}, err
	}
	var resp controlResponse
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func runAuthorizeCLI(a *Agent, args []string) {
	fs := flag.NewFlagSet("authorize", flag.ExitOnError)
	action := fs.String("action", "owner.session", "policy action")
	resource := fs.String("resource", "local:workstation", "policy resource")
	prompt := fs.String("prompt", "", "human-readable phone approval prompt")
	explicit := fs.Bool("explicit", false, "require an explicit on-phone approval")
	out := fs.String("out", "", "optional file for signed owner proof JSON")
	compact := fs.Bool("compact", false, "print compact JSON")
	_ = fs.Parse(args)
	resp, err := requestControl(a, controlRequest{Op: "authorize", Action: *action, Resource: *resource, Prompt: *prompt, Explicit: *explicit})
	if err != nil {
		fatal(err)
	}
	if !resp.Allowed {
		fmt.Printf("DENY: %s\n", resp.Reason)
		os.Exit(3)
	}
	fmt.Printf("ALLOW: %s\n", resp.Reason)
	if resp.Proof != nil {
		var b []byte
		if *compact {
			b, _ = json.Marshal(resp.Proof)
		} else {
			b, _ = json.MarshalIndent(resp.Proof, "", "  ")
		}
		fmt.Println(string(b))
		if *out != "" {
			if err := os.WriteFile(*out, b, 0600); err != nil {
				fatal(err)
			}
			fmt.Printf("Proof written: %s\n", *out)
		}
	}
}

func runGateCLI(a *Agent, args []string) {
	split := -1
	for i, s := range args {
		if s == "--" {
			split = i
			break
		}
	}
	var flagArgs, cmdArgs []string
	if split >= 0 {
		flagArgs = args[:split]
		cmdArgs = args[split+1:]
	} else {
		flagArgs = args
	}
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	action := fs.String("action", "owner.console", "policy action")
	resource := fs.String("resource", "local:owner-console", "policy resource")
	explicit := fs.Bool("explicit", false, "require explicit phone approval")
	prompt := fs.String("prompt", "", "human-readable phone approval prompt")
	_ = fs.Parse(flagArgs)
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "gate requires '-- <command> [args...]'")
		os.Exit(2)
	}
	resp, err := requestControl(a, controlRequest{Op: "authorize", Action: *action, Resource: *resource, Explicit: *explicit, Prompt: *prompt})
	if err != nil {
		fatal(err)
	}
	if !resp.Allowed || resp.Proof == nil {
		fmt.Printf("DENY: %s\n", resp.Reason)
		os.Exit(3)
	}
	proofs := filepath.Join(a.stateDir, "proofs")
	_ = os.MkdirAll(proofs, 0700)
	proofFile := filepath.Join(proofs, "latest-owner-proof.json")
	b, _ := json.MarshalIndent(resp.Proof, "", "  ")
	if err := os.WriteFile(proofFile, b, 0600); err != nil {
		fatal(err)
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ZORIN_TRUSTED=1", "ZORIN_OWNER_ACTION="+*action, "ZORIN_OWNER_RESOURCE="+*resource, "ZORIN_OWNER_PROOF_FILE="+proofFile, "ZORIN_PHONE_FINGERPRINT="+resp.Proof.PhoneFingerprint)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fatal(err)
	}
}

func runIdentityCLI(a *Agent, args []string) {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		fmt.Printf("Host identity: %s\nProvider: %s\nPublic DER: %x\n", a.hostFP, a.identity.Provider(), a.hostPub)
	case "migrate-tpm":
		if runtime.GOOS != "windows" {
			fatal(errors.New("TPM/CNG migration is only implemented on Windows in this milestone"))
		}
		id, err := migrateHostIdentityToTPM(a.stateDir)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("TPM identity ready.\nOld fingerprint: %s\nNew fingerprint: %s\nProvider: %s\n\nThe phone intentionally sees this as a NEW HOST. Run owner pairing again and approve the new fingerprint on-device.\n", a.hostFP, id.Fingerprint(), id.Provider())
	default:
		fmt.Fprintln(os.Stderr, "identity subcommands: status | migrate-tpm")
		os.Exit(2)
	}
}
