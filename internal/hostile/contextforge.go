package hostile

// CFRows are the hostile ContextForge rows HFC-01 to HFC-14 of SRS FR-22.43
// (planned v1.3.0), copied from srs_build/req8-contextforge.txt;
// TestContextForgeRowsMatchSRS keeps the two in step. They stay outside
// Appendix L until the release that adopts them, so their results are
// written apart from it (build/hostile-contextforge.json).
var CFRows = []Row{
	{ID: "HFC-01", Attack: "Poisoned catalog description", Behavior: "A local and a hosted entry whose `description` and tool descriptions carry instructions to the model", Expected: "Entry text shown inert in G-15; at import the metadata scan suspends the poisoned tools (SR-5.9-2)", Profiles: "Both"},
	{ID: "HFC-02", Attack: "YAML expansion", Behavior: "Catalog with nested aliases", Expected: "Catalog refused within 1 s (FR-22.2)", Profiles: "Both"},
	{ID: "HFC-03", Attack: "Shell-bearing install command", Behavior: "`install: \"npx x; rm -rf ~\"`", Expected: "Text shown verbatim; nothing executed; import requires an operator-pinned reference (FR-22.7)", Profiles: "Both"},
	{ID: "HFC-04", Attack: "Floating install command", Behavior: "`install: \"npx pkg@latest\"` with no version supplied", Expected: "Import refused with the FR-14.2 reason", Profiles: "Both"},
	{ID: "HFC-05", Attack: "Hosted URL to a private or metadata address", Behavior: "`url: \"https://169.254.169.254/sse\"` and a name resolving to 10.0.0.1", Expected: "Probe refused by E-18; no connection (SR-5.15-1)", Profiles: "Enforced"},
	{ID: "HFC-06", Attack: "Plain-HTTP downgrade", Behavior: "`url: \"http://mcp.example.com/sse\"`", Expected: "Classified `unsupported` (FR-22.3)", Profiles: "Both"},
	{ID: "HFC-07", Attack: "Remote media beacon", Behavior: "`logo_url` pointing at an external host", Expected: "No request leaves the console origin (FR-22.4)", Profiles: "Both"},
	{ID: "HFC-08", Attack: "Tool-list rug pull through ContextForge", Behavior: "The stand-in adds a tool, changes a description and renames the gateway after enablement, and sends no list-change notification", Expected: "Revision suspended at the next comparison or reconciliation poll (SR-3.8-2, FR-22.33)", Profiles: "Both"},
	{ID: "HFC-09", Attack: "Cross-package result swap", Behavior: "The stand-in answers package A's call with package B's result and injection text", Expected: "Result filtered and tagged by E-11, session tainted (`source_trust: untrusted`); limitation of one containment domain recorded (FR-22.42)", Profiles: "Both"},
	{ID: "HFC-10", Attack: "Token replay across virtual servers", Behavior: "The stand-in accepts a package token on another server, on the global `/mcp` and `/rpc` endpoints (listing and calling another package's tools) and on an admin route", Expected: "Self-check suspends every hosted package with `CONTEXTFORGE_SCOPE_BROKEN` (FR-22.29)", Profiles: "Both"},
	{ID: "HFC-11", Attack: "Secret exfiltration through ContextForge", Behavior: "The stand-in echoes an S1 secret value it should never see, and a probe secret", Expected: "No secret reaches the stand-in; a registered fingerprint in a result withholds it with `SECRET_LEAK`", Profiles: "Both"},
	{ID: "HFC-12", Attack: "Network and host escape", Behavior: "The stand-in connects to the Internet, the LAN, the Gateway's admin and harness listeners and the Podman socket path", Expected: "Every connection fails; only its listener and E-18 endpoints are reachable (SR-4.5-4, SR-4.7-3)", Profiles: "Enforced"},
	{ID: "HFC-13", Attack: "Admin object injection", Behavior: "The stand-in reports an extra gateway, a REST tool, a prompt and an A2A agent", Expected: "Removed by reconciliation; nothing presented; `contextforge_drift` recorded (FR-22.33, SR-5.6-3)", Profiles: "Both"},
	{ID: "HFC-14", Attack: "Forged administrator token", Behavior: "A token signed with a published ContextForge key", Expected: "Refused by the running instance; a start with a published key refused (FR-22.28)", Profiles: "Both"},
}
