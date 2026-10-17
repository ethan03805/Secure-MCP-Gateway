package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/tunnel"
)

const remoteUsage = `usage: smcpctl remote <enable|disable|status|check> [flags]

  enable   start the tunnel and enable the Remote Access Profile (Administrator)
           --provider tailscale|cloudflare|manual (default tailscale)
           --port 443|8443|10000   Funnel public port (tailscale)
           --public-url URL        public origin (manual, or to override)
  disable  disable the profile, end remote sessions, stop the tunnel
  status   show the profile and tunnel state
  check    check that the public name reaches the remote listener
           --public-url URL --ca FILE (trust a private CA for the check)
`

func remoteCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(remoteUsage))
	}
	switch args[0] {
	case "enable":
		return remoteEnable(args[1:], out)
	case "disable":
		return remoteDisable(args[1:], out)
	case "status":
		return remoteStatus(args[1:], out)
	case "check":
		return remoteCheck(args[1:], out)
	}
	return errors.New(strings.TrimSpace(remoteUsage))
}

func tunnelStatePath(cfg *config.Config) string {
	return filepath.Join(cfg.State.Dir, "remote", "tunnel.json")
}

func remoteEnable(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remote enable", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	provider := fs.String("provider", "tailscale", "tailscale, cloudflare or manual")
	port := fs.Int("port", 443, "Funnel public port (443, 8443 or 10000)")
	publicURL := fs.String("public-url", "", "public origin https://<name> (manual provider)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := cfg.Remote.Address
	st := tunnel.State{Provider: *provider, Target: target}
	var undo func()
	switch *provider {
	case "tailscale":
		ts := tunnel.NewTailscale()
		u, err := ts.PublicURL(ctx, *port)
		if err != nil {
			return err
		}
		if *publicURL == "" {
			*publicURL = u
		}
		// Enable the Gateway side first so the listener exists before the
		// public name forwards to it.
		st.Port = *port
		undo = func() { _ = ts.Disable(context.Background(), *port) }
		if _, _, err := c.do("POST", "/api/v1/remote/enable", map[string]any{"public_url": *publicURL, "provider": "tailscale"}); err != nil {
			return err
		}
		if err := ts.Enable(ctx, *port, target); err != nil {
			_, _, _ = c.do("POST", "/api/v1/remote/disable", map[string]any{})
			return fmt.Errorf("funnel: %w (remote access disabled again)", err)
		}
	case "cloudflare":
		cf := tunnel.NewCloudflare()
		pid, u, err := cf.Start(target, filepath.Join(cfg.State.Dir, "remote", "cloudflared.log"))
		if err != nil {
			return err
		}
		st.PID = pid
		if *publicURL == "" {
			*publicURL = u
		}
		undo = func() { _ = tunnel.Stop(pid) }
		if _, _, err := c.do("POST", "/api/v1/remote/enable", map[string]any{"public_url": *publicURL, "provider": "cloudflare"}); err != nil {
			undo()
			return err
		}
	case "manual", "vendor":
		if *publicURL == "" {
			return errors.New("--public-url is required with the manual provider")
		}
		if _, _, err := c.do("POST", "/api/v1/remote/enable", map[string]any{"public_url": *publicURL, "provider": *provider}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown provider %q", *provider)
	}
	st.PublicURL = *publicURL
	if err := tunnel.SaveState(tunnelStatePath(cfg), st); err != nil {
		if undo != nil {
			undo()
		}
		return err
	}
	fmt.Fprintf(out, "remote access enabled\n  public MCP URL: %s%s\n  provider: %s\n  forwards to: https://%s (loopback)\n", *publicURL, cfg.Listener.MCPPath, *provider, target)
	fmt.Fprintln(out, "Run `smcpctl remote check` to confirm the public name reaches the remote listener.")
	return nil
}

func remoteDisable(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remote disable", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	_, _, apiErr := c.do("POST", "/api/v1/remote/disable", map[string]any{})
	st, err := tunnel.LoadState(tunnelStatePath(cfg))
	if err != nil {
		return err
	}
	var tunErr error
	switch st.Provider {
	case "tailscale":
		tunErr = tunnel.NewTailscale().Disable(context.Background(), st.Port)
	case "cloudflare":
		tunErr = tunnel.Stop(st.PID)
	}
	if tunErr == nil {
		_ = tunnel.SaveState(tunnelStatePath(cfg), tunnel.State{})
	}
	fmt.Fprintln(out, "remote access disabled; remote sessions ended")
	if tunErr != nil {
		fmt.Fprintln(out, "tunnel teardown failed:", tunErr)
	} else if st.Provider != "" && st.Provider != "manual" {
		fmt.Fprintln(out, "tunnel stopped:", st.Provider)
	}
	return errors.Join(apiErr, tunErr)
}

func remoteStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remote status", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	res, _, err := c.do("GET", "/api/v1/remote", nil)
	if err != nil {
		return err
	}
	st, _ := tunnel.LoadState(tunnelStatePath(cfg))
	res["tunnel"] = st
	if st.Provider == "tailscale" {
		if raw, err := tunnel.NewTailscale().Status(context.Background()); err == nil {
			res["funnel_status"] = raw
		} else {
			res["funnel_status_error"] = err.Error()
		}
	}
	printJSON(out, res)
	return nil
}

func remoteCheck(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remote check", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	publicURL := fs.String("public-url", "", "public origin to check (default: the enabled one)")
	ca := fs.String("ca", "", "trust this CA for the check instead of the system roots")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	provider := "manual"
	if st, err := tunnel.LoadState(tunnelStatePath(cfg)); err == nil && st.Provider != "" {
		provider = st.Provider
		if *publicURL == "" {
			*publicURL = st.PublicURL
		}
	}
	if *publicURL == "" {
		c, err := newAdminClient(cfg, true)
		if err != nil {
			return err
		}
		res, _, err := c.do("GET", "/api/v1/remote", nil)
		if err != nil {
			return err
		}
		*publicURL, _ = res["public_url"].(string)
		if p, _ := res["provider"].(string); p != "" {
			provider = p
		}
	}
	if *publicURL == "" {
		return errors.New("no public URL: pass --public-url or enable remote access first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := tunnel.CheckPublic(ctx, provider, *publicURL, cfg.ResourceURI(), *ca)
	printJSON(out, res)
	if res.Listener != "remote" {
		return errors.New("remote check failed: " + res.Problem)
	}
	return nil
}
