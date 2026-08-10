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
	return PolicyConfig{Version: 5, DefaultEffect: "deny", Rules: []PolicyRule{
		{Action: "owner.session", Resource: "*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 30},
		{Action: "owner.console", Resource: "local:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 30},
		{Action: "credential.owner-proof", Resource: "*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
		{Action: "authority.authorize", Resource: "project:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
		{Action: "authority.authorize", Resource: "zauth:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
		{Action: "authority.project.manage", Resource: "project:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
		{Action: "ops.terminal", Resource: "vps:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
		{Action: "ops.docker.*", Resource: "vps:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
		{Action: "ops.docker.*", Resource: "vps:*/container:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
		{Action: "credential.ssh", Resource: "server:*", Effect: "deny", RequireTrust: true, ProofTTLSeconds: 60},
	}}
}

func ensurePolicy(stateDir string) (PolicyConfig, error) {
	p := filepath.Join(stateDir, "policy.json")
	if b, err := os.ReadFile(p); err == nil {
		var cfg PolicyConfig
		if json.Unmarshal(b, &cfg) == nil && cfg.Version > 0 {
			changed := false
			if cfg.Version < 2 {
				// Add only the new v0.6 capabilities. Existing user rules keep their
				// order and therefore continue to override later defaults.
				cfg.Rules = append(cfg.Rules,
					PolicyRule{Action: "authority.authorize", Resource: "project:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
					PolicyRule{Action: "ops.terminal", Resource: "vps:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
					PolicyRule{Action: "ops.docker.*", Resource: "vps:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
				)
				cfg.Version = 2
				changed = true
			}
			if cfg.Version < 3 {
				// ZAUTH/1 binds the complete transaction into a hash-scoped
				// authority resource instead of exposing project identifiers in the
				// phone-proof policy namespace. Keep project:* above for compatibility
				// with early v0.6 development builds.
				cfg.Rules = append(cfg.Rules,
					PolicyRule{Action: "authority.authorize", Resource: "zauth:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
				)
				cfg.Version = 3
				changed = true
			}
			if cfg.Version < 4 {
				// Docker resources include a slash-delimited container segment. Go's
				// path.Match does not let '*' cross '/', so the original vps:* rule
				// was insufficient for vps:<id>/container:<name>.
				cfg.Rules = append(cfg.Rules,
					PolicyRule{Action: "ops.docker.*", Resource: "vps:*/container:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 45},
				)
				cfg.Version = 4
				changed = true
			}
			if cfg.Version < 5 {
				// Managing Authority project origins changes which applications may
				// request owner assertions, so local UI mutations require an explicit
				// phone-approved owner proof.
				cfg.Rules = append(cfg.Rules,
					PolicyRule{Action: "authority.project.manage", Resource: "project:*", Effect: "allow", RequireTrust: true, ProofTTLSeconds: 60},
				)
				cfg.Version = 5
				changed = true
			}
			if changed {
				if out, err := json.MarshalIndent(cfg, "", "  "); err == nil {
					_ = os.WriteFile(p, out, 0600)
				}
			}
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
