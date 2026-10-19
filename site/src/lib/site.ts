import { execSync } from "node:child_process";
import type { ReqStatus, Status, StatusSnapshot } from "./status";
import { fmtDateTime, shortSha } from "./labels";
import { loadRequirements } from "./parse-reqs";

/* Formatting and status vocabulary live in labels.ts so client code can use them. */
export * from "./labels";

export const REPO_URL = "https://github.com/ethan03805/Secure-MCP-Gateway";

/** Site chapters, in reading order. The number is the chapter's section prefix. */
export const CHAPTERS = [
  { n: 1, href: "/status/", label: "Status", about: "Implementation, tests, coverage, requirement verification, acceptance scenarios AT-01 to AT-21, performance, real agents and hostile fixtures from the last CI run on main." },
  { n: 2, href: "/flows/", label: "Flows", about: "Every sequence and flow diagram, each with a numbered table of its steps." },
  { n: 3, href: "/architecture/", label: "Architecture", about: "The architecture document: decomposition, policy model, secrets, anomaly method." },
  { n: 4, href: "/elements/", label: "Elements", about: "Each element with trust level, implementation status, packages, requirements and interfaces." },
  { n: 5, href: "/interfaces/", label: "Interfaces", about: "External and internal interfaces, data stores, console view modules, open decisions." },
  { n: 6, href: "/requirements/", label: "Requirements", about: "Every requirement with its verification status, filterable by root, element, method and status." },
  { n: 7, href: "/security/", label: "Security controls", about: "The control hierarchy and the requirements that realize each control." },
  { n: 8, href: "/clients/", label: "Agents", about: "Real agent CLIs through the Gateway: results per client, per-agent notes, cloud agents and the Remote Access Profile." },
  { n: 9, href: "/docs/", label: "Documents", about: "Install, quick start, operator guide, references, client pages, runbooks, control API and the specification, rendered as written." },
  { n: 10, href: "/control-api/", label: "Control API", about: "Every control API operation with the roles that may use it, from the OpenAPI document generated from the Go sources." },
  { n: 11, href: "/install/", label: "Install", about: "Published releases, installation, and how to verify an archive (cosign, SHA-256, minisign) and a server package." },
] as const;

/** The user guide for people new to the product, linked ahead of the chapters. */
export const START_HERE = {
  href: "/docs/user-guide/",
  label: "Start here",
  about:
    "What you do with Secure MCP Gateway: install, connect your first agent, approve a call, read the journal, and the everyday tasks after that.",
} as const;

export type ChapterHref =(typeof CHAPTERS)[number]["href"];

export function chapter(href: ChapterHref) {
  return CHAPTERS.find((c) => c.href === href)!;
}

let stamp: string | null = null;

/** Short commit of the site build itself. */
export function buildCommit(): string {
  if (stamp) return stamp;
  const sha = process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7);
  if (sha) return (stamp = sha);
  try {
    stamp = execSync("git rev-parse --short HEAD", { cwd: process.cwd(), stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    stamp = "unknown";
  }
  return stamp;
}

/* Status joins ---------------------------------------------------------- */

export type ReqStatusEntry = { status: ReqStatus; tests: string[] };

/** Requirement ID to status, from the current items and the planned items of the CI report. */
export function reqStatusMap(s: Status): Map<string, ReqStatusEntry> {
  const all = [...s.requirements.items, ...(s.requirements.plannedItems ?? [])];
  return new Map(all.map((i) => [i.id, { status: i.status, tests: i.tests ?? [] }]));
}

let plannedIds: Set<string> | undefined;

/** IDs of the requirements whose source record has a TARGET: line (SRS Section 2.8). */
export function plannedRequirementIds(): Set<string> {
  plannedIds ??= new Set(loadRequirements().reqs.filter((r) => r.target).map((r) => r.id));
  return plannedIds;
}

/**
 * A requirement's status. Requirements absent from the CI report are unverified, and planned
 * (SRS Section 2.8) when their record names a target release, so the site is right even with
 * status data written before the report knew planned requirements.
 */
export function reqStatusOf(map: Map<string, ReqStatusEntry>, id: string): ReqStatus {
  const st = map.get(id)?.status ?? "unverified";
  return st === "unverified" && plannedRequirementIds().has(id) ? "planned" : st;
}

export function elementStatusMap(s: Status) {
  return new Map(s.elements.map((e) => [e.id, e]));
}

/** One line describing the data source, for headers and footers. */
export function dataSourceLine(snap: StatusSnapshot): string {
  return snap.source === "remote"
    ? `CI run at commit ${shortSha(snap.status.commit)}, generated ${fmtDateTime(snap.status.generatedAt)}`
    : "sample data, not from CI";
}
