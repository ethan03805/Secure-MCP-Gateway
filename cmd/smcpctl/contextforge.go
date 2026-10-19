package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
)

const contextforgeUsage = `usage: smcpctl contextforge <status|start|stop> [--config smcp.toml] [--json]

The bundled ContextForge instance ([contextforge] bundled = true) of the
running Gateway. start verifies the pinned image (cosign signature and
SBOM attestation for the release lock's signer) before its first start and
after an image change, then starts it on a loopback port with credentials
from the Secret Vault. stop stops it; its data volume stays.
`

func contextforgeCmd(args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "status" && args[0] != "start" && args[0] != "stop") {
		fmt.Fprint(out, contextforgeUsage)
		return errors.New("contextforge: subcommand status, start or stop required")
	}
	fs := flag.NewFlagSet("contextforge "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, err := catalogClient(*cfgPath)
	if err != nil {
		return err
	}
	var inst map[string]any
	switch args[0] {
	case "status":
		res, _, err := c.do("GET", "/api/v1/contextforge/status", nil)
		if err != nil {
			return err
		}
		inst, _ = res["instance"].(map[string]any)
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
