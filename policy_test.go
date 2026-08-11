package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicy(t *testing.T) {
	cfg := defaultPolicy()
	if !evaluatePolicy(cfg, "owner.console", "local:demo", true).Allowed {
		t.Fatal("owner console should be allowed while trusted")
	}
	if evaluatePolicy(cfg, "owner.console", "local:demo", false).Allowed {
		t.Fatal("owner console must require trust")
	}
	if evaluatePolicy(cfg, "credential.ssh", "server:prod", true).Allowed {
		t.Fatal("ssh must be denied by default")
	}
	if !evaluatePolicy(cfg, "authority.authorize", "zauth:012345", true).Allowed {
		t.Fatal("ZAUTH transaction scopes should be allowed while trusted")
	}
	if !evaluatePolicy(cfg, "ops.docker.restart", "vps:prod/container:web", true).Allowed {
		t.Fatal("Docker container resources should be allowed while trusted")
	}
}

func TestPolicyV2MigrationAddsZAUTHScope(t *testing.T) {
	dir := t.TempDir()
	cfg := PolicyConfig{Version: 2, DefaultEffect: "deny", Rules: []PolicyRule{{Action: "authority.authorize", Resource: "project:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60}}}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ensurePolicy(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 6 {
		t.Fatalf("expected policy v6, got %d", got.Version)
	}
	if !evaluatePolicy(got, "authority.authorize", "zauth:abcdef", true).Allowed {
		t.Fatal("migrated policy must allow transaction-bound ZAUTH scopes")
	}
	if !evaluatePolicy(got, "authority.project.manage", "project:demo", true).Allowed {
		t.Fatal("migrated policy must allow explicit Authority project management")
	}
	if !evaluatePolicy(got, "authority.ssh.issue", "sshcert:abcdef", true).Allowed {
		t.Fatal("migrated policy must allow transaction-bound SSH certificate issuance")
	}
	if !evaluatePolicy(got, "ops.ssh-ca.enroll", "vps:prod", true).Allowed {
		t.Fatal("migrated policy must allow explicit SSH CA enrollment")
	}
	if !evaluatePolicy(got, "ops.node.install", "vps:prod", true).Allowed {
		t.Fatal("migrated policy must allow explicit Zorin Node installation")
	}
}
