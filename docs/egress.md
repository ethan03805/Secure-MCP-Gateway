# Egress Broker (E-18)

The Egress Broker is the only path from a backend server instance to a network destination. It forwards an operation only when a grant for the instance's server alias names the destination host, port and method, resolves the destination name itself, refuses reserved addresses, bounds size, duration and rate, and records every operation in the evidence journal.

The broker is off by default. Enable it with `[egress] enabled = true`.

## What enforces it

| Profile | Platform | What the broker does | What stops a server from going around it |
|---|---|---|---|
| Enforced | Linux, rootless Podman launcher with slirp4netns and nftables | Binds the instance's listeners on the host's 127.0.0.1 and passes them to the container as `10.0.2.2:<port>`; the launcher installs nftables rules in the container's network namespace before the server starts | The nftables rules: the namespace can reach only TCP to its own broker listeners. Everything else, including DNS, UDP and ICMP, is rejected. |
| Standalone | macOS, or Linux without a confining launcher | Binds the instance's listeners on `127.0.0.1` and passes their addresses in the instance environment | Nothing. The proxy variables are advisory: a server that ignores `HTTP_PROXY` or opens sockets itself reaches the network directly. Any local process can also connect to an instance's listeners and use that server's grants. The release label is "not enforced". |

The rootless Podman launcher (E-16) attaches each `[[runtime.server]]` with `network = "egress"` through `pipeline.EgressAttacher` and confines the container's network namespace itself, because only the rootless user namespace that owns it can change its nftables rules: `podman create` on slirp4netns with host loopback, `podman init`, then `podman unshare nsenter --net=<namespace> nft -f -` installs table `inet smcp_egress`, reads it back, and only then starts the server. Any failure removes the container. The steps are in [sandbox.md](sandbox.md#egress). In the standalone profile egress is advisory.

## How an instance reaches a destination

Each instance gets its own listeners, so the broker knows which server sends each operation.

- **Forward proxy.** `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy` and `https_proxy` are set to `http://<address>:<port>`. `NO_PROXY` and `no_proxy` are set to the empty string. HTTPS goes through `CONNECT host:port`; the broker checks the grant, resolves and validates the address, then reads the TLS ClientHello and requires its server name (SNI) to equal the CONNECT host. The TLS session is not terminated or inspected: the server sees the destination's own certificate. Plain HTTP goes as absolute-form requests (`GET http://host/path`).
- **Endpoints.** A grant with `endpoint_env` also gets a plain-HTTP listener whose base URL is passed in that variable, for example `API_URL=http://127.0.0.1:41871`. A request to `$API_URL/v1/items?x=1` is sent to `https://<host>:<port>/v1/items?x=1`. The broker originates TLS and validates the destination certificate against the system trust store. Endpoints follow redirects to destinations the instance is also granted, re-validating each target, at most 3 times. Public-fetch grants are served only through an endpoint.

Variables from the broker replace configured `[server.env]` variables of the same name.

**S1 secret headers (FR-6.6).** The broker implements `pipeline.SecretHeaderInjector` for the Secret Broker (E-20). An S1 binding names a header, a template such as `Bearer {secret}` and a destination (`host` or `host:port`). The broker inserts the header on endpoint requests to that destination, where it originates the TLS itself, and replaces any value the instance sent for that header. It never inserts a header into forward-proxy requests (plain HTTP, or CONNECT tunnels it does not terminate), and it applies the header again on each redirect hop, so a redirect to another host loses it. A grant is withdrawn, and its value overwritten, at instance teardown, emergency stop and broker shutdown. `smcpd` connects the two brokers when `[egress] enabled = true` and `[secrets]` is configured.

On every forwarded operation the broker removes `Cookie` from the request, `Set-Cookie` and `Set-Cookie2` from the response, the `Smcp-Egress-Auth` header, hop-by-hop headers and `Proxy-Authorization`. It keeps no cookie state and opens a new connection for each operation. Protocol upgrades (WebSocket) are refused. Cookies inside a CONNECT tunnel are encrypted and pass unchanged.

## Addresses

The broker resolves names with the host's resolver, never the instance's. It refuses an address in any of these classes unless the grant lists the exact address in `addresses`:

| Class | IPv4 | IPv6 |
|---|---|---|
| loopback | 127.0.0.0/8 | ::1 |
| private | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | fc00::/7 |
| link-local | 169.254.0.0/16 | fe80::/10, any address with a zone |
| cgnat | 100.64.0.0/10 | |
| multicast | 224.0.0.0/4 | ff00::/8 |
| cloud-metadata | 169.254.169.254, 169.254.170.2, 100.100.100.200, 192.0.0.192 | fd00:ec2::254, fd20:ce::254 |
| reserved | 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4 | ::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 3fff::/20, 5f00::/16, fec0::/10, everything outside 2000::/3 |

IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses are classified by the IPv4 address they carry.

The broker dials the IP address it validated, never the name. A DNS answer that changes between operations (rebinding) is validated again on the next operation and refused if it is reserved.

## Configuration

```toml
[egress]
enabled = true                 # default false
proxy_env = true               # default true: set HTTP_PROXY and HTTPS_PROXY
request_bytes = 1048576        # default 1 MiB; request body, or bytes sent through a tunnel
response_bytes = 8388608       # default 8 MiB; response body, or bytes received through a tunnel
operation_timeout = "30s"      # default 30s; whole operation, including a tunnel's lifetime
dial_timeout = "10s"           # default 10s; DNS, TCP connect, TLS handshake, ClientHello read
requests_per_minute = 60       # default 60; per server alias, all instances together
bytes_per_minute = 67108864    # default 64 MiB; per server alias, both directions
recent_records = 256           # default 256; operation records kept for the control API

[[egress.grant]]
server = "web"                 # server alias (required)
host = "api.example.com"       # exact name, "*.example.com" (subdomains only) or IP literal (required)
ports = [443]                  # default [443]
methods = ["GET", "POST", "CONNECT-TLS"]   # required; CONNECT-TLS permits HTTPS tunnels
class = "api"                  # "api" (default) or "public-fetch"
endpoint_env = "API_URL"       # optional: plain-HTTP endpoint for https://host:port
addresses = []                 # exact reserved addresses this grant may reach
request_bytes = 0              # optional, only smaller than [egress]; 0 keeps the default
response_bytes = 0             # optional, only smaller than [egress]
timeout = "10s"                # optional, only shorter than [egress]
```

Rules checked when the configuration loads:

- `server` must name a configured `[[server]]` alias.
- A grant with `endpoint_env` needs an exact host (no wildcard) and exactly one port; an `endpoint_env` name is used once per server.
- `class = "public-fetch"` needs `endpoint_env` and `methods = ["GET"]`. Public-fetch permits HTTPS GET only, without a request body, `Authorization` header, upgrade or CONNECT.
- `addresses` entries must be IP addresses.
- `methods` are upper case: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `CONNECT-TLS`.

Grants come from the configuration until the policy service (E-05, E-06) provides egress grants from decision obligations. The broker reads the current grants on every operation.

## Evidence

Each operation writes journal events of class `egress` and origin `E-18`:

| Phase | Outcome | When |
|---|---|---|
| (none) | `attached`, `detached` | An instance's listeners open or close |
| `authorized` | `allow` | After the destination is validated and before any byte of the instance's request is forwarded. If the journal refuses this event, the operation is refused with `EGRESS_EVIDENCE_UNAVAILABLE`. |
| `completed` | `completed` | The operation ended normally |
| `denied` | `deny` | The operation was refused before forwarding, or a redirect or address was refused |
| `failed` | `terminated` | A forwarded operation was cut by a limit, a timeout or an upstream failure |

The event detail holds the operation record: `id`, `time`, `instance`, `server`, `mode` (`connect`, `http` or `endpoint`), `method`, `host`, `port`, `path`, `sni`, `grant`, `resolved` (every address the name resolved to), `address` (the address dialed), `address_class`, `redirects`, `decision` (`allowed` or `denied`), `reason`, `detail`, `status`, `bytes_up`, `bytes_down`, `duration_ms` and `injected_headers` (names of S1 headers the broker inserted). Query strings, header values and bodies are not recorded.

## Commands

All read the running Gateway's control API with the local operator token.

| Command | Shows |
|---|---|
| `smcpctl egress status [--config f]` | Limits, attached instances, their proxy and endpoint URLs, and whether each is enforced or advisory |
| `smcpctl egress grants [--server alias]` | Current grants with their effective limits |
| `smcpctl egress connections [--server alias] [--denied] [--limit n] [--since time]` | Recent operation records, newest first. `--denied` shows refused and terminated operations. `--since` takes an RFC 3339 time. |

The routes are documented in [api/egress.md](api/egress.md).

## Reason codes

The instance receives the HTTP status below with the reason code in the `Smcp-Egress-Reason` response header and a one-line plain-text body. For a CONNECT tunnel that is refused after the tunnel was opened (SNI, not TLS), the connection is closed; the reason is in the evidence.

| Reason code | HTTP | Meaning | Next action |
|---|---|---|---|
| `EGRESS_NO_GRANT` | 403 | No grant of the server names this host and port | Add an `[[egress.grant]]` for the server if the destination is intended |
| `EGRESS_METHOD_REFUSED` | 403 | The destination is granted, but not for this method (or not for `CONNECT-TLS`) | Add the method to the grant's `methods` |
| `EGRESS_BAD_REQUEST` | 400 | Malformed target, origin-form request sent to the proxy, absolute-form or CONNECT sent to an endpoint, or a protocol upgrade | Use the proxy for absolute URLs and CONNECT, and the endpoint for paths |
| `EGRESS_ADDRESS_REFUSED` | 403 | The destination resolves only to reserved addresses (`address_class` in the record) | If the destination is a local service on purpose, list its exact address in `addresses` |
| `EGRESS_DNS_FAILED` | 502 | The broker could not resolve the name | Check the host's DNS |
| `EGRESS_SNI_MISMATCH` | connection closed | The TLS server name differs from the CONNECT host, or is missing for a name | The server must connect with the granted host name as SNI |
| `EGRESS_NOT_TLS` | connection closed | A CONNECT tunnel did not start with a TLS ClientHello | Tunnels carry TLS only; use plain-HTTP proxying for `http://` |
| `EGRESS_RATE_LIMITED` | 429 | `requests_per_minute` of the server reached | Raise the limit or reduce the server's request rate |
| `EGRESS_BYTE_RATE_LIMITED` | 429, or connection cut | `bytes_per_minute` of the server reached | Raise the limit |
| `EGRESS_REQUEST_TOO_LARGE` | 413, or connection cut | Request body or tunnel upload above the limit | Raise `request_bytes` |
| `EGRESS_RESPONSE_TOO_LARGE` | 502, or connection cut | Response body or tunnel download above the limit | Raise `response_bytes` |
| `EGRESS_TIMEOUT` | 504, or connection cut | `operation_timeout` (or the grant's `timeout`) reached | Raise the timeout |
| `EGRESS_UPSTREAM_FAILED` | 502 | Connection, TLS validation or protocol failure at the destination | Check the destination and its certificate |
| `EGRESS_REDIRECT_REFUSED` | 403 | An endpoint was redirected to an ungranted, non-HTTPS or malformed target, or more than 3 times | Grant the redirect target, or call the final URL directly |
| `EGRESS_PUBLIC_FETCH_PROFILE` | 403 | A public-fetch grant was used with a request body, an `Authorization` header or as plain HTTP through the proxy (CONNECT and methods other than GET are refused with `EGRESS_METHOD_REFUSED`) | Public-fetch is for anonymous HTTPS GET through its endpoint |
| `EGRESS_EVIDENCE_UNAVAILABLE` | 503 | The journal refused the authorization event | See `smcpctl health`; the journal must be writable |
| `EGRESS_SECRET_DETECTED` | 403 | A registered secret (a value the Secret Broker delivered) appears in the URL, a header or the body of a brokered HTTP request; only the header the broker inserts for S1 delivery is exempt (SR-5.8-2). The bytes of a CONNECT tunnel are TLS the broker does not terminate and are not scanned | Deliver the credential as S1 so the broker inserts it, instead of sending it from the server |

## Kernel test

`scripts/ci-egress-netns.sh` builds the egress test binary and runs `TestNetnsEnforcement` as root. It creates a network namespace connected to the host with a veth pair, checks that the namespace can reach a local HTTP server directly, attaches the namespace to the broker, and then checks that direct connections fail, a brokered request to the granted server succeeds, a brokered request to another server is refused with `EGRESS_NO_GRANT`, and that detaching removes the rules. It uses no Internet access. The linux-integration CI job runs it on ubuntu-24.04.

## Not yet implemented

- One-use egress capabilities in `Smcp-Egress-Auth` (SR-5.16-1) are deferred from release 1.0 (SRS Appendix N): third-party servers do not send them. Each operation is authorized by the instance it comes from and its current grants (SR-4.5-2); the header is removed before forwarding.
- The `secret-fingerprint` filter on outbound URLs, headers and bodies (SR-5.8-2).
- Grants from policy decision obligations and limits from manifests and Runtime Profiles (FR-5.38 names three sources; the broker applies the configuration and the grant).
- Endpoint variable names from signed manifests (FR-5.37); today they come from `endpoint_env` in the configuration.
- Egress observables for the Observation Collector (E-29) beyond the journal events.
