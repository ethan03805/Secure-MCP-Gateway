// Package bundle runs the bundled ContextForge instance of the ContextForge
// Connector (E-36, SRS FR-22.18 to FR-22.32, planned for v1.3.0): the
// generated, hardened configuration (FR-22.27), the generated credentials
// and their checks (FR-22.28), the loopback-only listener on a port chosen
// at each start (FR-22.26), the container lifecycle and the health checks
// (FR-22.30), and the administrator token for the admin API (I-43).
package bundle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReasonConfigRefused: the effective configuration of the bundled
// instance differs from the generated one (FR-22.27, FR-22.37).
const ReasonConfigRefused = "CONTEXTFORGE_CONFIG_REFUSED"

// ContainerPort is the instance's listener inside its container.
const ContainerPort = 4444

// AdminEmail is the platform administrator's address. ContextForge does
// not validate the address of the administrator it bootstraps.
const AdminEmail = "smcp-admin@example.com"

// disabledKeys are the ContextForge features the Gateway neither needs nor
// mediates (FR-22.27). Every one is set to false.
var disabledKeys = []string{
	"MCPGATEWAY_UI_ENABLED",
	"MCPGATEWAY_CATALOG_ENABLED",
	"PLUGINS_ENABLED",
	"LLMCHAT_ENABLED",
	"MCPGATEWAY_A2A_ENABLED",
	"MCPGATEWAY_REVERSE_PROXY_ENABLED",
	"MCPGATEWAY_WS_RELAY_ENABLED",
	"MCPGATEWAY_DIRECT_PROXY_ENABLED",
	"MCPGATEWAY_MCP_APPS_ENABLED",
	"MCPGATEWAY_STDIO_TRANSPORT_ENABLED",
	"MCPGATEWAY_BULK_IMPORT_ENABLED",
	"MCPGATEWAY_TOOL_PREVIEW_ENABLED",
	"MCPGATEWAY_GRPC_ENABLED",
	"MCPGATEWAY_ELICITATION_ENABLED",
	"PUBLIC_REGISTRATION_ENABLED",
	"SSO_ENABLED",
	"SSO_GITHUB_ENABLED",
	"SSO_GOOGLE_ENABLED",
	"SSO_IBM_VERIFY_ENABLED",
	"SSO_OKTA_ENABLED",
	"SSO_KEYCLOAK_ENABLED",
	"SSO_ENTRA_ENABLED",
	"SSO_ADFS_ENABLED",
	"SSO_GENERIC_ENABLED",
	"SSO_API_TOKEN_AUTH_ENABLED",
	"OBSERVABILITY_ENABLED",
	"OTEL_ENABLE_OBSERVABILITY",
	"OTEL_HTTPX_INSTRUMENTATION_ENABLED",
	"OTEL_SQLALCHEMY_INSTRUMENTATION_ENABLED",
	"OTEL_REDIS_INSTRUMENTATION_ENABLED",
	"STRUCTURED_LOGGING_EXTERNAL_ENABLED",
	"ELASTICSEARCH_ENABLED",
	"SYSLOG_ENABLED",
	"WEBHOOK_LOGGING_ENABLED",
	"SIEM_EXPORT_ENABLED",
	"SMTP_ENABLED",
	"DCR_ENABLED",
	"PASSWORD_RESET_ENABLED",
	"CORS_ENABLED",
	"INSECURE_ALLOW_QUERYPARAM_AUTH",
	"DOCS_ALLOW_BASIC_AUTH",
	"SKIP_SSL_VERIFY",
	"SSRF_ALLOW_LOCALHOST",
	"SSRF_ALLOW_PRIVATE_NETWORKS",
	"DEV_MODE",
	"TOOLOPS_ENABLED",
}

// enabledKeys must be true (FR-22.27).
var enabledKeys = []string{
	"EMAIL_AUTH_ENABLED",
	"AUTH_REQUIRED",
	"MCP_CLIENT_AUTH_ENABLED",
	"REQUIRE_JTI",
	"REQUIRE_TOKEN_EXPIRATION",
	"SSRF_PROTECTION_ENABLED",
	"SSRF_DNS_FAIL_CLOSED",
	"JWT_AUDIENCE_VERIFICATION",
	"JWT_ISSUER_VERIFICATION",
}

// Credential keys (FR-22.28).
const (
	KeyJWTSecret        = "JWT_SECRET_KEY"
	KeyEncryptionSecret = "AUTH_ENCRYPTION_SECRET"
	KeyBasicAuth        = "BASIC_AUTH_PASSWORD"
	KeyAdminPassword    = "PLATFORM_ADMIN_PASSWORD"
	KeyDefaultUser      = "DEFAULT_USER_PASSWORD"
)

// CredentialKeys are the five instance credentials.
var CredentialKeys = []string{KeyJWTSecret, KeyEncryptionSecret, KeyBasicAuth, KeyAdminPassword, KeyDefaultUser}

// Limits are the Gateway's limits that the instance's own must exceed
// (FR-22.37): CP-13 upstream timeout, CP-11 calls per minute, CP-10 total
// tool concurrency.
type Limits struct {
	UpstreamTimeout time.Duration
	CallsPerMinute  int
	Concurrency     int
}

// Settings are the non-secret inputs of the generated configuration.
type Settings struct {
	// SSRFAllowed are the E-18 endpoint networks the instance may reach
	// (CIDR, FR-22.27); empty allows none.
	SSRFAllowed []string
	Limits      Limits
}

// Environment returns the generated, non-secret configuration of the
// bundled instance. The credentials are added from the vault at start and
// never written to a file (FR-22.28).
func Environment(s Settings) map[string]string {
	env := map[string]string{}
	for _, k := range disabledKeys {
		env[k] = "false"
	}
	for _, k := range enabledKeys {
		env[k] = "true"
	}
	nets := s.SSRFAllowed
	if nets == nil {
		nets = []string{}
	}
	raw, _ := json.Marshal(nets)
	timeout := int((2*s.Limits.UpstreamTimeout + time.Second - 1) / time.Second)
	env["SSRF_ALLOWED_NETWORKS"] = string(raw)
	env["GUNICORN_WORKERS"] = "1"
	env["GATEWAY_TOOL_NAME_SEPARATOR"] = "-"
	env["ALLOWED_ORIGINS"] = ""
	env["OTEL_TRACES_EXPORTER"] = "none"
	env["HOST"] = "0.0.0.0" // inside the container; the host publishes it on loopback only (FR-22.26)
	env["PORT"] = strconv.Itoa(ContainerPort)
	env["ENVIRONMENT"] = "production"
	env["CACHE_TYPE"] = "database"
	env["DATABASE_URL"] = "sqlite:////app/data/mcp.db"
	env["PLATFORM_ADMIN_EMAIL"] = AdminEmail
	env["BASIC_AUTH_USER"] = "smcp"
	env["TOOL_TIMEOUT"] = strconv.Itoa(timeout)
	env["TOOL_RATE_LIMIT"] = strconv.Itoa(2 * s.Limits.CallsPerMinute)
	env["TOOL_CONCURRENT_LIMIT"] = strconv.Itoa(2 * s.Limits.Concurrency)
	return env
}

// CheckEnvironment refuses an effective configuration that differs from
// the generated rules, naming the key (FR-22.27, FR-22.37): every disabled
// key false, every enabled key true, one worker, the "-" separator, no
// allowed origin, an SSRF allowlist of CIDR networks only, and tool limits
// at least twice the Gateway's.
func CheckEnvironment(env map[string]string, l Limits) error {
	bad := func(k, why string) error {
		return packaging.Errf(ReasonConfigRefused, "bundled ContextForge configuration: %s %s", k, why)
	}
	for _, k := range disabledKeys {
		if v, ok := env[k]; !ok || !strings.EqualFold(v, "false") {
			return bad(k, "must be false")
		}
	}
	for _, k := range enabledKeys {
		if v, ok := env[k]; !ok || !strings.EqualFold(v, "true") {
			return bad(k, "must be true")
		}
	}
	if env["GUNICORN_WORKERS"] != "1" {
		return bad("GUNICORN_WORKERS", "must be 1")
	}
	if env["GATEWAY_TOOL_NAME_SEPARATOR"] != "-" {
		return bad("GATEWAY_TOOL_NAME_SEPARATOR", "must be -")
	}
	if v, ok := env["ALLOWED_ORIGINS"]; !ok || v != "" {
		return bad("ALLOWED_ORIGINS", "must be empty")
	}
	var nets []string
	if err := json.Unmarshal([]byte(env["SSRF_ALLOWED_NETWORKS"]), &nets); err != nil {
		return bad("SSRF_ALLOWED_NETWORKS", "must be a JSON list of networks")
	}
	for _, n := range nets {
		if !strings.Contains(n, "/") {
			return bad("SSRF_ALLOWED_NETWORKS", fmt.Sprintf("entry %q is not a network", n))
		}
	}
	min := map[string]int{
		"TOOL_TIMEOUT":          int((2*l.UpstreamTimeout + time.Second - 1) / time.Second),
		"TOOL_RATE_LIMIT":       2 * l.CallsPerMinute,
		"TOOL_CONCURRENT_LIMIT": 2 * l.Concurrency,
	}
	keys := make([]string, 0, len(min))
	for k := range min {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n, err := strconv.Atoi(env[k])
		if err != nil || n < min[k] {
			return bad(k, fmt.Sprintf("must be at least %d (twice the Gateway's limit)", min[k]))
		}
	}
	for _, k := range CredentialKeys {
		if _, ok := env[k]; ok {
			return bad(k, "must not be part of the generated configuration (it comes from the vault)")
		}
	}
	return nil
}
