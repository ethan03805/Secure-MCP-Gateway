// The view modules G-01 to G-14 of ArchitectureV2 §4 (E-24) plus the
// operator views of elements that have no G number. The navigation lists
// the views the signed-in role may open (FR-8.28).
import type { ReactNode } from "react";
import type { Role } from "../api";
import { Approvals } from "./Approvals";
import { Audit } from "./Audit";
import { Control } from "./Control";
import { Generic, type Endpoint } from "./Generic";
import { Servers } from "./Servers";
import { Sessions } from "./Sessions";

export interface ViewDef {
  code?: string;
  title: string;
  path: string;
  group: "Operate" | "Policy" | "Approvals and evidence" | "Observation and research";
  roles: Role[];
  /** Path prefixes this view also owns (detail pages). */
  prefixes?: string[];
  render: (path: string) => ReactNode;
}

const admin: Role[] = ["administrator"];

function generic(code: string | undefined, title: string, lede: string, help: string, endpoints: Endpoint[]) {
  return (path: string) => <Generic key={path} code={code} title={title} lede={lede} help={help} endpoints={endpoints} />;
}

export const views: ViewDef[] = [
  { code: "G-01", title: "Gateway control", path: "/", group: "Operate", roles: admin, render: () => <Control /> },
  { code: "G-11", title: "Sessions and principals", path: "/sessions", prefixes: ["/sessions/"], group: "Operate", roles: admin, render: (p) => <Sessions path={p} /> },
  { code: "G-10", title: "Servers and library", path: "/servers", prefixes: ["/servers/", "/catalog"], group: "Operate", roles: admin, render: (p) => <Servers path={p} /> },
  {
    code: "G-12",
    title: "Secrets",
    path: "/secrets",
    group: "Operate",
    roles: admin,
    render: generic(
      "G-12",
      "Secrets",
      "Secret metadata, Secret Use Policy bindings and rotation. Values are write-only and are never shown.",
      "Secrets are created and rotated with the Secret Vault (E-19). This view lists metadata only: names, slots, bindings and rotation dates.",
      [{ label: "Secrets", route: "/api/v1/secrets" }],
    ),
  },
  {
    title: "Egress",
    path: "/egress",
    group: "Operate",
    roles: admin,
    render: generic(
      undefined,
      "Egress",
      "Network destinations that server instances may reach through the Egress Broker (E-18).",
      "Each row is a destination granted by policy. Traffic to anything else is dropped by the host firewall in the Enforced profile.",
      [
        { label: "Egress broker", route: "/api/v1/egress" },
        { label: "Egress grants", route: "/api/v1/egress/grants" },
        { label: "Connections", route: "/api/v1/egress/connections" },
      ],
    ),
  },
  {
    title: "Runtime",
    path: "/runtime",
    group: "Operate",
    roles: admin,
    render: generic(
      undefined,
      "Runtime",
      "Server instances in the execution sandbox and what the Runtime Monitor (E-17) observed.",
      "Instances are listed with their sandbox profile and resource limits. In the Standalone profile there is no sandbox and this view stays empty.",
      [
        { label: "Runtime", route: "/api/v1/runtime" },
        { label: "Instances", route: "/api/v1/runtime/instances" },
      ],
    ),
  },
  {
    title: "Remote access",
    path: "/remote",
    group: "Operate",
    roles: admin,
    render: generic(
      undefined,
      "Remote access",
      "The Remote Access Profile and the OAuth client registrations waiting for approval.",
      "Remote access is off by default. Dynamic client registrations stay pending until an Administrator approves them here or with smcpctl clients approve.",
      [
        { label: "Remote access", route: "/api/v1/remote" },
        { label: "Client registrations", route: "/api/v1/clients" },
      ],
    ),
  },
  {
    code: "G-02",
    title: "Policy studio",
    path: "/policy",
    group: "Policy",
    roles: admin,
    render: generic(
      "G-02",
      "Policy studio",
      "Framework Profiles, Session Allow templates, Response and Secret Use Policies: drafts, diffs, simulation and publication.",
      "The active revision is enforced by every call. Use Reload policy on Gateway control to activate the policy file after editing it; the policy service adds drafts, diff and simulation.",
      [{ label: "Policy revisions", route: "/api/v1/policy" }],
    ),
  },
  {
    code: "G-03",
    title: "Audit profile tuning",
    path: "/audit-profiles",
    group: "Policy",
    roles: admin,
    render: generic(
      "G-03",
      "Audit profile tuning",
      "The mandatory audit floor, which cannot be lowered, and the optional capture, retention and alert settings.",
      "Mandatory events (decisions, call phases, administrative actions) are always journaled. Audit Profiles add optional capture on top.",
      [{ label: "Audit profiles", route: "/api/v1/policy/audit-profiles" }],
    ),
  },
  {
    code: "G-06",
    title: "Anomaly response",
    path: "/anomaly-response",
    group: "Policy",
    roles: admin,
    render: generic(
      "G-06",
      "Anomaly response",
      "What the Gateway does at each sigma band: log, alert, escalate capture, require approval, withhold or suspend.",
      "Actions can only restrict a call, never widen what policy permits.",
      [{ label: "Response policy", route: "/api/v1/anomalies/policy" }],
    ),
  },
  { code: "G-13", title: "Approvals", path: "/approvals", prefixes: ["/approvals/"], group: "Approvals and evidence", roles: ["administrator", "approver"], render: (p) => <Approvals path={p} /> },
  { code: "G-14", title: "Audit investigation", path: "/audit", prefixes: ["/audit/"], group: "Approvals and evidence", roles: admin, render: (p) => <Audit path={p} /> },
  {
    code: "G-04",
    title: "Observation workbench",
    path: "/observations",
    group: "Observation and research",
    roles: admin,
    render: generic(
      "G-04",
      "Observation workbench",
      "Choose parameters from the Parameter Catalog, set scope, sampling and baseline contexts, and see the cost before publishing.",
      "Parameters come from the catalog data, so a parameter added by a release appears here without a console change.",
      [
        { label: "Parameter catalog", route: "/api/v1/observations/catalog" },
        { label: "Observation policies", route: "/api/v1/observations/policies" },
      ],
    ),
  },
  {
    code: "G-05",
    title: "Behavior analytics",
    path: "/analytics",
    group: "Observation and research",
    roles: admin,
    render: generic(
      "G-05",
      "Behavior analytics",
      "Baselines per context, abnormal events and baseline snapshots.",
      "A baseline is promoted only after review; until then scoring uses the previous snapshot.",
      [
        { label: "Baselines", route: "/api/v1/baselines" },
        { label: "Anomalies", route: "/api/v1/anomalies" },
      ],
    ),
  },
  {
    code: "G-07",
    title: "Performance",
    path: "/performance",
    group: "Observation and research",
    roles: admin,
    render: generic(
      "G-07",
      "Performance",
      "Throughput, gateway-added latency per stage and the time cost of each policy rule and filter.",
      "Figures come from the Health & Safety Monitor. The loopback /metrics endpoint carries the same counters for Prometheus.",
      [{ label: "Performance", route: "/api/v1/health/performance" }],
    ),
  },
  {
    code: "G-08",
    title: "Data server and memory",
    path: "/data-server",
    group: "Observation and research",
    roles: admin,
    render: generic(
      "G-08",
      "Data server and memory",
      "Memory use against budget, store sizes, degradation stage and the last backup.",
      "The Data Server is optional; enforcement never waits for it.",
      [
        { label: "Data server", route: "/api/v1/health/data" },
        { label: "Backups", route: "/api/v1/backup" },
      ],
    ),
  },
  {
    code: "G-09",
    title: "Research campaigns",
    path: "/research",
    group: "Observation and research",
    roles: admin,
    render: generic(
      "G-09",
      "Research campaigns",
      "Capture campaigns, their approval, dataset exports and data dictionaries.",
      "A campaign captures more than the default observation policy for a bounded time and needs approval before it starts.",
      [{ label: "Campaigns", route: "/api/v1/research/campaigns" }],
    ),
  },
];

export function viewFor(path: string): ViewDef | undefined {
  return (
    views.find((v) => v.path === path) ??
    views.find((v) => v.prefixes?.some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p || path.startsWith(p + "/"))))
  );
}
