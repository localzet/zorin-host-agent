package main

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type PolicyRule struct {
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	Effect          string `json:"effect"`
	RequireTrust    bool   `json:"require_trust"`
	ProofTTLSeconds int    `json:"proof_ttl_seconds"`
}

type PolicyConfig struct {
	Version       int          `json:"version"`
	DefaultEffect string       `json:"default_effect"`
	Rules         []PolicyRule `json:"rules"`
}

type PolicyDecision struct {
	Allowed bool        `json:"allowed"`
	Reason  string      `json:"reason"`
	Rule    *PolicyRule `json:"rule,omitempty"`
}

func defaultPolicy() PolicyConfig {
	return PolicyConfig{Version: 1, DefaultEffect: "deny", Rules: []PolicyRule{
		{Action: "owner.session", Resource: "*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 30},
		{Action: "owner.console", Resource: "local:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 30},
		{Action: "credential.owner-proof", Resource: "*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
		{Action: "credential.ssh", Resource: "server:*", Effect: "deny", RequireTrust: true, ProofTTLSeconds: 60},
	}}
}

func ensurePolicy(stateDir string) (PolicyConfig, error) {
	p := filepath.Join(stateDir, "policy.json")
	if b, err := os.ReadFile(p); err == nil {
		var cfg PolicyConfig
		if json.Unmarshal(b, &cfg) == nil && cfg.Version > 0 {
			return cfg, nil
		}
	}
	cfg := defaultPolicy()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(p, b, 0600); err != nil {
		return PolicyConfig{}, err
	}
	return cfg, nil
}

func loadPolicy(stateDir string) PolicyConfig {
	cfg, err := ensurePolicy(stateDir)
	if err != nil {
		return defaultPolicy()
	}
	return cfg
}

func matchPolicy(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, value)
	if err == nil && ok {
		return true
	}
	return strings.EqualFold(pattern, value)
}

func evaluatePolicy(cfg PolicyConfig, action, resource string, trusted bool) PolicyDecision {
	for i := range cfg.Rules {
		r := cfg.Rules[i]
		if !matchPolicy(r.Action, action) || !matchPolicy(r.Resource, resource) {
			continue
		}
		if r.RequireTrust && !trusted {
			return PolicyDecision{Allowed: false, Reason: "trusted owner session required", Rule: &r}
		}
		allow := strings.EqualFold(r.Effect, "allow")
		reason := "matched policy rule: " + r.Effect
		return PolicyDecision{Allowed: allow, Reason: reason, Rule: &r}
	}
	return PolicyDecision{Allowed: strings.EqualFold(cfg.DefaultEffect, "allow"), Reason: "default policy: " + cfg.DefaultEffect}
}
