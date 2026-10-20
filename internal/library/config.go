package library

import (
	"errors"
	"log/slog"
	"path/filepath"
	"runtime"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// OpenConfigured opens the library named by a Gateway configuration. With
// [runtime] sandbox = "appcontainer" (the Windows machine mode, FR-21.13)
// each enabled revision gets its AppContainer placement, recorded under
// <state>/appcontainer.
func OpenConfigured(cfg *config.Config, log *slog.Logger) (*Library, error) {
	o := Options{StateDir: cfg.State.Dir, Dir: cfg.Packages.Library, Log: log}
	if cfg.Runtime.Sandbox == "appcontainer" {
		if runtime.GOOS != "windows" {
			return nil, errors.New(`runtime.sandbox = "appcontainer" needs Windows`)
		}
		o.Containment = winsandbox.Placements{Dir: filepath.Join(cfg.State.Dir, "appcontainer")}
		o.Bindings = func(serverID string) (SlotBinding, bool) {
			for _, s := range cfg.Servers {
				if s.Package == serverID {
					return SlotBinding{Alias: s.Alias, Slots: s.Slots}, true
				}
			}
			return SlotBinding{}, false
		}
	}
	return Open(o)
}

// Interpreters returns the configured runtime paths.
func Interpreters(cfg *config.Config) packaging.Interpreters {
	return packaging.Interpreters{Node: cfg.Packages.Node, Python: cfg.Packages.Python, Podman: cfg.Packages.Podman}
}

// OpenRuntime opens the library and its Gateway runtime from the
// configuration (smcpd).
func OpenRuntime(cfg *config.Config, log *slog.Logger) (*Runtime, error) {
	lib, err := OpenConfigured(cfg, log)
	if err != nil {
		return nil, err
	}
	return NewRuntime(lib, RuntimeOptions{Interp: Interpreters(cfg), RequireSigned: cfg.Packages.RequireSigned,
		ScanInterval: cfg.Packages.ScanInterval.Duration, Log: log, EgressGrants: egressGrants(cfg)}), nil
}

// egressGrants returns the configured egress grants when the Egress Broker
// is enabled; without it no grant takes effect.
func egressGrants(cfg *config.Config) []config.EgressGrant {
	if !cfg.Egress.Enabled {
		return nil
	}
	return cfg.Egress.Grants
}
