package main

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const policyVersion = 7

type PolicyRule struct {
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	Effect          string `json:"effect"`
	RequireTrust    bool   `json:"require_trust"`
	RequirePresence bool   `json:"require_presence,omitempty"`
	RequireExplicit bool   `json:"require_explicit,omitempty"`
	ProofTTLSeconds int    `json:"proof_ttl_seconds"`
}

type PolicyConfig struct {
	Version       int          `json:"version"`
	DefaultEffect string       `json:"default_effect"`
	Rules         []PolicyRule `json:"rules"`
}

type PolicyContext struct {
	Trusted      bool
	OwnerPresent bool
}

type PolicyDecision struct {
	Allowed         bool        `json:"allowed"`
	Reason          string      `json:"reason"`
	RequireExplicit bool        `json:"require_explicit"`
	Rule            *PolicyRule `json:"rule,omitempty"`
}

func defaultPolicy() PolicyConfig {
	return PolicyConfig{
		Version:       policyVersion,
		DefaultEffect: "deny",
		Rules: []PolicyRule{
			{
				Action:          "owner.session",
				Resource:        "*",
				Effect:          "allow",
				RequireTrust:    true,
				RequirePresence: true,
				ProofTTLSeconds: 30,
			},
			{
				Action:          "owner.console",
				Resource:        "local:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequirePresence: true,
				ProofTTLSeconds: 30,
			},
			{
				Action:          "credential.owner-proof",
				Resource:        "*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "authority.authorize",
				Resource:        "project:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "authority.authorize",
				Resource:        "zauth:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "authority.project.manage",
				Resource:        "project:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "authority.ssh.issue",
				Resource:        "sshcert:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "ops.ssh-ca.enroll",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "ops.node.install",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 60,
			},
			{
				Action:          "ops.terminal",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequirePresence: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "ops.docker.*",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "ops.docker.*",
				Resource:        "vps:*/container:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "os.pam.authenticate",
				Resource:        "user:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "os.sudo.authorize",
				Resource:        "user:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "os.windows.sensitive",
				Resource:        "local:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			{
				Action:          "credential.ssh",
				Resource:        "server:*",
				Effect:          "deny",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
		},
	}
}

func ensurePolicy(stateDir string) (PolicyConfig, error) {
	policyPath := filepath.Join(stateDir, "policy.json")

	if raw, err := os.ReadFile(policyPath); err == nil {
		var cfg PolicyConfig
		if json.Unmarshal(raw, &cfg) == nil && cfg.Version > 0 {
			if migratePolicy(&cfg) {
				if err := writePolicy(policyPath, cfg); err != nil {
					return PolicyConfig{}, err
				}
			}
			return cfg, nil
		}
	}

	cfg := defaultPolicy()
	if err := writePolicy(policyPath, cfg); err != nil {
		return PolicyConfig{}, err
	}
	return cfg, nil
}

func migratePolicy(cfg *PolicyConfig) bool {
	changed := false

	// Старые миграции оставляем пошаговыми: пользовательские правила сохраняют
	// свой порядок и, соответственно, приоритет над добавленными дефолтами.
	if cfg.Version < 2 {
		cfg.Rules = append(cfg.Rules,
			PolicyRule{
				Action:          "authority.authorize",
				Resource:        "project:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
			PolicyRule{
				Action:          "ops.terminal",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 45,
			},
			PolicyRule{
				Action:          "ops.docker.*",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 45,
			},
		)
		cfg.Version = 2
		changed = true
	}

	if cfg.Version < 3 {
		cfg.Rules = append(cfg.Rules, PolicyRule{
			Action:          "authority.authorize",
			Resource:        "zauth:*",
			Effect:          "allow",
			RequireTrust:    true,
			ProofTTLSeconds: 60,
		})
		cfg.Version = 3
		changed = true
	}

	if cfg.Version < 4 {
		cfg.Rules = append(cfg.Rules, PolicyRule{
			Action:          "ops.docker.*",
			Resource:        "vps:*/container:*",
			Effect:          "allow",
			RequireTrust:    true,
			ProofTTLSeconds: 45,
		})
		cfg.Version = 4
		changed = true
	}

	if cfg.Version < 5 {
		cfg.Rules = append(cfg.Rules, PolicyRule{
			Action:          "authority.project.manage",
			Resource:        "project:*",
			Effect:          "allow",
			RequireTrust:    true,
			ProofTTLSeconds: 60,
		})
		cfg.Version = 5
		changed = true
	}

	if cfg.Version < 6 {
		cfg.Rules = append(cfg.Rules,
			PolicyRule{
				Action:          "authority.ssh.issue",
				Resource:        "sshcert:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
			PolicyRule{
				Action:          "ops.ssh-ca.enroll",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
			PolicyRule{
				Action:          "ops.node.install",
				Resource:        "vps:*",
				Effect:          "allow",
				RequireTrust:    true,
				ProofTTLSeconds: 60,
			},
		)
		cfg.Version = 6
		changed = true
	}

	if cfg.Version < policyVersion {
		// Начиная с 0.9 степень подтверждения задаёт policy, а не вызывающий
		// клиент. Так чувствительный вызов нельзя случайно ослабить, забыв
		// передать explicit=true.
		markExplicit(cfg, "credential.owner-proof", "*")
		markExplicit(cfg, "authority.authorize", "project:*")
		markExplicit(cfg, "authority.authorize", "zauth:*")
		markExplicit(cfg, "authority.project.manage", "project:*")
		markExplicit(cfg, "authority.ssh.issue", "sshcert:*")
		markExplicit(cfg, "ops.ssh-ca.enroll", "vps:*")
		markExplicit(cfg, "ops.node.install", "vps:*")
		markExplicit(cfg, "ops.docker.*", "vps:*")
		markExplicit(cfg, "ops.docker.*", "vps:*/container:*")
		markPresence(cfg, "owner.session", "*")
		markPresence(cfg, "owner.console", "local:*")
		markPresence(cfg, "ops.terminal", "vps:*")

		cfg.Rules = append(cfg.Rules,
			PolicyRule{
				Action:          "os.pam.authenticate",
				Resource:        "user:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			PolicyRule{
				Action:          "os.sudo.authorize",
				Resource:        "user:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
			PolicyRule{
				Action:          "os.windows.sensitive",
				Resource:        "local:*",
				Effect:          "allow",
				RequireTrust:    true,
				RequireExplicit: true,
				ProofTTLSeconds: 45,
			},
		)

		cfg.Version = policyVersion
		changed = true
	}

	return changed
}

func markExplicit(cfg *PolicyConfig, action, resource string) {
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if rule.Action == action && rule.Resource == resource {
			rule.RequireExplicit = true
		}
	}
}

func markPresence(cfg *PolicyConfig, action, resource string) {
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if rule.Action == action && rule.Resource == resource {
			rule.RequirePresence = true
		}
	}
}

func writePolicy(policyPath string, cfg PolicyConfig) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(policyPath, raw, 0600)
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

func evaluatePolicy(
	cfg PolicyConfig,
	action string,
	resource string,
	context PolicyContext,
) PolicyDecision {
	for i := range cfg.Rules {
		rule := cfg.Rules[i]
		if !matchPolicy(rule.Action, action) || !matchPolicy(rule.Resource, resource) {
			continue
		}

		if rule.RequireTrust && !context.Trusted {
			return PolicyDecision{
				Allowed: false,
				Reason:  "trusted owner session required",
				Rule:    &rule,
			}
		}

		// Explicit approval умеет дождаться разблокировки телефона, поэтому
		// отсутствие presence здесь не является немедленным отказом.
		if rule.RequirePresence && !rule.RequireExplicit && !context.OwnerPresent {
			return PolicyDecision{
				Allowed: false,
				Reason:  "owner presence required: phone is locked",
				Rule:    &rule,
			}
		}

		allowed := strings.EqualFold(rule.Effect, "allow")
		return PolicyDecision{
			Allowed:         allowed,
			Reason:          "matched policy rule: " + rule.Effect,
			RequireExplicit: rule.RequireExplicit,
			Rule:            &rule,
		}
	}

	return PolicyDecision{
		Allowed: strings.EqualFold(cfg.DefaultEffect, "allow"),
		Reason:  "default policy: " + cfg.DefaultEffect,
	}
}
