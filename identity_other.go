//go:build !windows

package main

import "path/filepath"

func loadHostIdentity(stateDir string) (HostIdentity, error) {
	return loadOrCreateLegacyIdentity(filepath.Join(stateDir, "host-identity.pem"))
}

func migrateHostIdentityToTPM(stateDir string) (HostIdentity, error) {
	return loadHostIdentity(stateDir)
}
