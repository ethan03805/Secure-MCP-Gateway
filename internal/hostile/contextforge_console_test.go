//go:build hostile

package hostile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
)

func init() { cfChecks["HFC-07"] = hfc07 }

// HFC-07: a catalog entry whose logo_url points at an external host. The
// console page of G-15 is served under a Content-Security-Policy that lets
// the browser load images, scripts, styles, fonts and API calls from the
// console origin only, so the remote logo cannot be fetched; the catalog
// route returns the logo URL as data, which G-15 shows as text. (The
// console job's Playwright suite also watches the browser's requests,
// console/e2e/contextforge.spec.ts.)
func hfc07(t *testing.T) (string, bool) {
	logo := "https://beacon.attacker.example/pixel.png"
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "beacon", URL: "https://beacon.example.com/mcp", LogoURL: logo}}})
	g := e.StartGateway(cfharness.GatewayOptions{Approve: true})
	resp, err := g.HTTP.Get(g.Cfg.AdminURL() + "/contextforge/catalog/beacon")
	if err != nil {
		return "console page: " + err.Error(), false
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	directives := map[string]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			directives[f[0]] = strings.Join(f[1:], " ")
		}
	}
	confined := directives["default-src"] == "'none'" && directives["img-src"] == "'self'" && directives["connect-src"] == "'self'" &&
		directives["script-src"] == "'self'" && directives["style-src"] == "'self'" && directives["font-src"] == "'self'" &&
		!strings.Contains(csp, "http") && !strings.Contains(csp, "*")
	req, _ := http.NewRequest(http.MethodGet, g.Cfg.AdminURL()+"/api/v1/contextforge/catalog/beacon", nil)
	req.Header.Set("Authorization", "Bearer "+g.Operator())
	resp, err = g.HTTP.Do(req)
	if err != nil {
		return "catalog route: " + err.Error(), false
	}
	var entry struct {
		Fields map[string]any `json:"fields"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	asText := entry.Fields["logo_url"] == logo
	return fmt.Sprintf("console CSP admits images and requests from the console origin only: %v (%s); the logo URL is served as data: %v", confined, csp, asText),
		resp.StatusCode == http.StatusOK && confined && asText
}
