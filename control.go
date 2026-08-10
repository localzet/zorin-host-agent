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
	Token    string `json:"token"`
	Op       string `json:"op"`
	Action   string `json:"action,omitempty"`
	Resource string `json:"resource,omitempty"`
}

type controlResponse struct {
	OK      bool        `json:"ok"`
	Allowed bool        `json:"allowed,omitempty"`
	Reason  string      `json:"reason,omitempty"`
	Proof   *OwnerProof `json:"proof,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (a *Agent) serveControl() error {
	ln, err := net.Listen("tcp", controlAddr)
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
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
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
		resp := a.authorize(req.Action, req.Resource)
		_ = json.NewEncoder(c).Encode(resp)
	case "status":
		a.mu.Lock()
		trusted := len(a.live) > 0
		present := false
		for _, s := range a.live {
			if s.userPresent {
				present = true
				break
			}
		}
		a.mu.Unlock()
		reason := "no trusted device session"
		if trusted && present {
			reason = "trusted device + owner presence"
		} else if trusted {
			reason = "trusted device; phone locked"
		}
		_ = json.NewEncoder(c).Encode(controlResponse{OK: true, Allowed: trusted, Reason: reason})
	default:
		_ = json.NewEncoder(c).Encode(controlResponse{Error: "unsupported control operation"})
	}
}

func (a *Agent) authorize(action, resource string) controlResponse {
	action = strings.TrimSpace(action)
	resource = strings.TrimSpace(resource)
	if action == "" || resource == "" {
		return controlResponse{Error: "action and resource are required"}
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
	d := evaluatePolicy(cfg, action, resource, trusted)
	if !d.Allowed {
		a.recordEvent("authority-denied", "warning", "Owner action denied", action+" -> "+resource+": "+d.Reason, "", nil)
		return controlResponse{OK: true, Allowed: false, Reason: d.Reason}
	}
	if live == nil {
		return controlResponse{OK: true, Allowed: false, Reason: "trusted session disappeared"}
	}
	if !present {
		a.recordEvent("authority-denied", "info", "Owner action blocked while locked", action+" -> "+resource, live.phoneFP, nil)
		return controlResponse{OK: true, Allowed: false, Reason: "owner presence required: phone is locked"}
	}
	ttl := 30
	if d.Rule != nil && d.Rule.ProofTTLSeconds > 0 {
		ttl = d.Rule.ProofTTLSeconds
	}
	pr := proofRequest{action: action, resource: resource, ttl: ttl, result: make(chan proofResult, 1)}
	select {
	case live.req <- pr:
	case <-time.After(2 * time.Second):
		return controlResponse{Error: "phone proof queue unavailable"}
	}
	select {
	case r := <-pr.result:
		if r.err != nil {
			a.recordEvent("proof-error", "warning", "Owner proof failed", r.err.Error(), live.phoneFP, nil)
			return controlResponse{Error: r.err.Error()}
		}
		a.recordEvent("proof-issued", "success", "Owner proof issued", action+" -> "+resource, live.phoneFP, nil)
		return controlResponse{OK: true, Allowed: true, Reason: d.Reason, Proof: &r.proof}
	case <-time.After(7 * time.Second):
		return controlResponse{Error: "phone proof request timed out"}
	}
}

func requestControl(a *Agent, req controlRequest) (controlResponse, error) {
	req.Token = a.controlToken
	c, err := net.DialTimeout("tcp", controlAddr, 2*time.Second)
	if err != nil {
		return controlResponse{}, fmt.Errorf("host agent control API is not running: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
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
	out := fs.String("out", "", "optional file for signed owner proof JSON")
	compact := fs.Bool("compact", false, "print compact JSON")
	_ = fs.Parse(args)
	resp, err := requestControl(a, controlRequest{Op: "authorize", Action: *action, Resource: *resource})
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
	_ = fs.Parse(flagArgs)
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "gate requires '-- <command> [args...]'")
		os.Exit(2)
	}
	resp, err := requestControl(a, controlRequest{Op: "authorize", Action: *action, Resource: *resource})
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
