package main

import "testing"

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
}
