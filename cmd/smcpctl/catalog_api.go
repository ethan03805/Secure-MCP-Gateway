package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// catalogPoll is how often `smcpctl catalog import` asks whether a
// proposal is built, and catalogWait how long it waits.
var (
	catalogPoll = 500 * time.Millisecond
	catalogWait = 16 * time.Minute
)

func catalogClient(cfgPath string) (*adminClient, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	return newAdminClient(cfg, true)
}

func sval(v any) string {
	s, _ := v.(string)
	return s
}

func catalogStatusAPI(c *adminClient, out io.Writer, asJSON bool) error {
	res, _, err := c.do("GET", "/api/v1/contextforge/status", nil)
	if err != nil {
		return err
	}
	if asJSON {
		printJSON(out, res)
		return nil
	}
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	if e := sval(res["catalog_error"]); e != "" {
		fmt.Fprintf(tw, "catalog\trefused (%s): %s\n", sval(res["catalog_reason_code"]), inert(e, 200))
	} else {
		fmt.Fprintf(tw, "catalog\t%s %s, sha256 %s, %v entries\n", sval(res["catalog_origin"]), sval(res["catalog_release"]), sval(res["catalog_sha256"]), res["catalog_entries"])
	}
	if l, ok := res["release_lock"].(map[string]any); ok {
		fmt.Fprintf(tw, "release lock\tContextForge %s, image %s\n", sval(l["version"]), sval(l["image_index_digest"]))
	}
	fmt.Fprintf(tw, "bundled instance\t%v\n", res["bundled"])
	if k, ok := res["import_key"].(map[string]any); ok {
		state := "not enrolled: an Administrator enrolls it with smcpctl trust add (see below)"
		if k["enrolled"] == true {
			state = fmt.Sprintf("enrolled for %v", k["classes"])
		}
		fmt.Fprintf(tw, "catalog import key\t%s, %s\n", sval(k["key_id"]), state)
		if k["enrolled"] != true {
			fmt.Fprintf(tw, "public key\t%s\n", sval(k["public_key"]))
		}
	}
	return tw.Flush()
}

func catalogListAPI(c *adminClient, out io.Writer, q url.Values, asJSON bool) error {
	for k, v := range q {
		if len(v) == 0 || v[0] == "" {
			q.Del(k)
		}
	}
	path := "/api/v1/contextforge/catalog"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	res, _, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	if asJSON {
		printJSON(out, res)
		return nil
	}
	entries, _ := res["entries"].([]any)
	fmt.Fprintf(out, "catalog sha256 %s (%s %s), %d of %v entries\n", sval(res["catalog_sha256"]), sval(res["origin"]), sval(res["release"]), len(entries), res["total"])
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLASS\tAUTH\tIMPORT\tURL OR INSTALL")
	for _, x := range entries {
		e, _ := x.(map[string]any)
		ref := sval(e["url"])
		if sval(e["class"]) == "local" {
			ref = sval(e["install"])
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", inert(sval(e["id"]), 40), sval(e["class"]), inert(sval(e["auth_type"]), 20), sval(e["import_state"]), inert(ref, 60))
	}
	return tw.Flush()
}

func catalogShowAPI(c *adminClient, out io.Writer, id string) error {
	res, _, err := c.do("GET", "/api/v1/contextforge/catalog/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	printJSON(out, res)
	return nil
}

// catalogImportAPI starts an import, waits for the build, prints the trust
// decision and applies --accept or --decline, or asks on a terminal.
func catalogImportAPI(c *adminClient, out io.Writer, id string, body map[string]any, accept string, decline bool) error {
	res, _, err := c.do("POST", "/api/v1/contextforge/catalog/"+url.PathEscape(id)+"/import", body)
	if err != nil {
		return err
	}
	p, _ := res["proposal"].(map[string]any)
	pid := sval(p["proposal_id"])
	fmt.Fprintf(out, "proposal %s: fetching the pinned artifact and probing it\n", pid)
	deadline := time.Now().Add(catalogWait)
	for sval(p["state"]) == "building" {
		if time.Now().After(deadline) {
			return fmt.Errorf("proposal %s is still building; check it later with smcpctl catalog decide", pid)
		}
		time.Sleep(catalogPoll)
		res, _, err = c.do("GET", "/api/v1/contextforge/proposals/"+url.PathEscape(pid), nil)
		if err != nil {
			return err
		}
		p, _ = res["proposal"].(map[string]any)
	}
	if sval(p["state"]) != "ready" {
		return fmt.Errorf("import refused: %s (%s)", sval(p["error"]), sval(p["reason_code"]))
	}
	d, _ := p["decision"].(map[string]any)
	sum := sval(d["sha256"])
	fmt.Fprintf(out, "\nTrust decision (sha256 %s):\n\n%s\n", sum, sval(d["text"]))
	switch {
	case decline:
		return catalogDecide(c, out, pid, "", true)
	case accept != "":
		return catalogDecide(c, out, pid, accept, false)
	case stdinIsTerminal():
		fmt.Fprint(out, "Type accept to sign and import this package, or anything else to decline: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) == "accept" {
			return catalogDecide(c, out, pid, sum, false)
		}
		return catalogDecide(c, out, pid, "", true)
	default:
		fmt.Fprintf(out, "The proposal waits for a decision for one hour:\n  smcpctl catalog decide %s --accept %s\n  smcpctl catalog decide %s --decline\n", pid, sum, pid)
		return nil
	}
}

func catalogDecide(c *adminClient, out io.Writer, pid, accept string, decline bool) error {
	body := map[string]any{"accept": !decline, "presented_sha256": accept}
	res, _, err := c.do("POST", "/api/v1/contextforge/proposals/"+url.PathEscape(pid)+"/decision", body)
	if err != nil {
		return err
	}
	p, _ := res["proposal"].(map[string]any)
	switch sval(p["outcome"]) {
	case "imported":
		fmt.Fprintf(out, "imported %s@%s as verified-disabled; an Administrator enables it (smcpctl package enable) and a policy grants its tools\n", sval(p["server_id"]), sval(p["revision"]))
	case "declined":
		fmt.Fprintln(out, "declined; nothing was signed or imported")
	default:
		return errors.New("unexpected decision result: " + sval(p["outcome"]))
	}
	return nil
}
