package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

const contextforgeUsage = `usage: smcpctl contextforge <status|start|stop|uninstall> [--config smcp.toml] [--json]
       smcpctl contextforge upgrade [--lock contextforge.lock.json [--signature FILE]] [--config smcp.toml] [--json]

The bundled ContextForge instance ([contextforge] bundled = true) of the
running Gateway. start verifies the pinned image (cosign signature and
SBOM attestation for the release lock's signer) before its first start and
after an image change, then starts it on a loopback port with credentials
from the Secret Vault. stop stops it; its data volume stays. uninstall
(Administrator) removes it, its data volume and image, retires its
credentials and suspends every enabled hosted package; the journal and
the hosted packages' Library records stay.

upgrade (Operator) changes the instance's ContextForge release: without
--lock to the release lock of this Gateway when it pins a newer release,
with --lock to that release lock, whose minisign signature (--signature,
default the lock file name with .minisig) must verify with the release
key. The data of the instance is backed up first; when the new release
fails verification, health within 60 seconds, reconciliation or the
registration of an enabled hosted package, the previous release and its
data are restored.
`

func contextforgeCmd(args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "status" && args[0] != "start" && args[0] != "stop" && args[0] != "uninstall" && args[0] != "upgrade") {
		fmt.Fprint(out, contextforgeUsage)
		return errors.New("contextforge: subcommand status, start, stop, uninstall or upgrade required")
	}
	fs := flag.NewFlagSet("contextforge "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "JSON output")
	lockPath := fs.String("lock", "", "upgrade: a release lock to upgrade to")
	sigPath := fs.String("signature", "", "upgrade: the lock's minisign signature (default <lock>.minisig)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, err := catalogClient(*cfgPath)
	if err != nil {
		return err
	}
	var inst map[string]any
	switch args[0] {
	case "upgrade":
		body := map[string]any{}
		if *lockPath != "" {
			raw, err := os.ReadFile(*lockPath)
			if err != nil {
				return err
			}
			if *sigPath == "" {
				*sigPath = *lockPath + ".minisig"
			}
			sig, err := os.ReadFile(*sigPath)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			body["lock"], body["signature"] = string(raw), string(sig)
		} else if *sigPath != "" {
			return errors.New("contextforge upgrade: --signature needs --lock")
		}
		res, _, err := c.do("POST", "/api/v1/contextforge/instance/upgrade", body)
		if res == nil && err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
			return err
		}
		rep, _ := res["upgrade"].(map[string]any)
		switch sval(rep["outcome"]) {
		case "upgraded":
			fmt.Fprintf(out, "upgraded the bundled ContextForge instance from %s to %s; hosted packages registered again: %v\n", sval(rep["from"]), sval(rep["to"]), rep["hosted_packages_checked"])
		case "rolled_back":
			fmt.Fprintf(out, "the upgrade from %s to %s failed at %s (%s); ContextForge %s and its data were restored\n",
				sval(rep["from"]), sval(rep["to"]), sval(rep["failed_step"]), inert(sval(rep["error"]), 300), sval(rep["from"]))
		}
		return err
	case "status":
		res, _, err := c.do("GET", "/api/v1/contextforge/status", nil)
		if err != nil {
			return err
		}
		inst, _ = res["instance"].(map[string]any)
	case "uninstall":
		res, _, err := c.do("POST", "/api/v1/contextforge/instance/uninstall", map[string]any{})
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
			return nil
		}
		rep, _ := res["uninstall"].(map[string]any)
		fmt.Fprintf(out, "removed the bundled ContextForge instance: %v credentials retired, volume removed %v, image removed %v, suspended %v\n",
			rep["credentials_retired"], rep["volume_removed"], rep["image_removed"], rep["suspended_revisions"])
		return nil
	default:
		res, _, err := c.do("POST", "/api/v1/contextforge/instance/"+args[0], map[string]any{})
		if err != nil {
			return err
		}
		inst, _ = res["instance"].(map[string]any)
	}
	if *asJSON {
		printJSON(out, inst)
		return nil
	}
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "state\t%s\n", sval(inst["state"]))
	if d := sval(inst["detail"]); d != "" {
		fmt.Fprintf(tw, "detail\t%s\n", inert(d, 300))
	}
	fmt.Fprintf(tw, "version\t%s\n", sval(inst["version"]))
	fmt.Fprintf(tw, "image\t%s\n", sval(inst["image"]))
	verified := sval(inst["verified"])
	if verified == "" {
		verified = "not yet"
	}
	fmt.Fprintf(tw, "image verified\t%s\n", verified)
	if inst["unconfined"] == true && sval(inst["state"]) != "disabled" {
		fmt.Fprintf(tw, "containment\tnot enforced (Standalone profile)\n")
	}
	return tw.Flush()
}
