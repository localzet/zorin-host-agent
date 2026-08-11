package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPolicy(t *testing.T) {
	cfg := defaultPolicy()
	present := PolicyContext{Trusted: true, OwnerPresent: true}
	locked := PolicyContext{Trusted: true, OwnerPresent: false}
	offline := PolicyContext{}

	if !evaluatePolicy(cfg, "owner.console", "local:demo", present).Allowed {
		t.Fatal("owner console should be allowed with owner presence")
	}
	if evaluatePolicy(cfg, "owner.console", "local:demo", locked).Allowed {
		t.Fatal("owner console should require presence")
	}
	if evaluatePolicy(cfg, "owner.console", "local:demo", offline).Allowed {
		t.Fatal("owner console should require trust")
	}
	if evaluatePolicy(cfg, "credential.ssh", "server:prod", present).Allowed {
		t.Fatal("standing SSH credential should stay denied")
	}

	checks := []struct {
		action   string
		resource string
	}{
		{"authority.authorize", "zauth:012345"},
		{"ops.docker.restart", "vps:prod/container:web"},
		{"os.pam.authenticate", "user:ivan"},
		{"os.sudo.authorize", "user:ivan"},
		{"os.windows.sensitive", "local:settings"},
	}

	for _, check := range checks {
		decision := evaluatePolicy(cfg, check.action, check.resource, locked)
		if !decision.Allowed {
			t.Fatalf("%s should be policy-allowed while explicit approval waits: %s", check.action, decision.Reason)
		}
		if !decision.RequireExplicit {
			t.Fatalf("%s must force explicit approval", check.action)
		}
	}
}

func TestPolicyMigrationToV7(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	old := PolicyConfig{
		Version:       6,
		DefaultEffect: "deny",
		Rules: []PolicyRule{
			{
				Action:          "authority.ssh.issue",
				Resource:        "sshcert:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "ops.terminal",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 45,
			},
		},
	}

	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ensurePolicy(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != policyVersion {
		t.Fatalf("version=%d want=%d", got.Version, policyVersion)
	}

	sshDecision := evaluatePolicy(got, "authority.ssh.issue", "sshcert:abcdef", PolicyContext{Trusted: true})
	if !sshDecision.Allowed || !sshDecision.RequireExplicit {
		t.Fatal("migrated SSH issuance must force explicit approval")
	}

	terminalDecision := evaluatePolicy(got, "ops.terminal", "vps:prod", PolicyContext{Trusted: true})
	if terminalDecision.Allowed {
		t.Fatal("migrated terminal rule must require owner presence")
	}

	pamDecision := evaluatePolicy(got, "os.pam.authenticate", "user:ivan", PolicyContext{Trusted: true})
	if !pamDecision.Allowed || !pamDecision.RequireExplicit {
		t.Fatal("PAM rule was not added during migration")
	}
}
