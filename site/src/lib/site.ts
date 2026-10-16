import { execSync } from "node:child_process";
import type { ReqStatus, Status, StatusSnapshot } from "./status";
import { fmtDateTime, shortSha } from "./labels";

/* Formatting and status vocabulary live in labels.ts so client code can use them. */
export * from "./labels";

export const REPO_URL = "https://github.com/ethan03805/Secure-MCP-Gateway";

/** Site chapters, in reading order. The number is the chapter's section prefix. */
export const CHAPTERS = [
  { n: 1, href: "/status/", label: "Status", about: "Implementation, tests, coverage and requirement verification from the last CI run on main." },
  { n: 2, href: "/flows/", label: "Flows", about: "Every sequence and flow diagram, each with a numbered table of its steps." },
  { n: 3, href: "/architecture/", label: "Architecture", about: "The architecture document: decomposition, policy model, secrets, anomaly method." },
  { n: 4, href: "/elements/", label: "Elements", about: "Each element with trust level, implementation status, packages, requirements and interfaces." },
  { n: 5, href: "/interfaces/", label: "Interfaces", about: "External and internal interfaces, data stores, console view modules, open decisions." },
  { n: 6, href: "/requirements/", label: "Requirements", about: "Every requirement with its verification status, filterable by root, element, method and status." },
  { n: 7, href: "/security/", label: "Security controls", about: "The control hierarchy and the requirements that realize each control." },
  { n: 8, href: "/clients/", label: "Clients", about: "What Claude Code, Codex and Hermes expect, and how the specification meets them." },
  { n: 9, href: "/docs/", label: "Documents", about: "The source documents, rendered as written." },
] as const;

export type ChapterHref = (typeof CHAPTERS)[number]["href"];

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

/** Requirement ID to status. Requirements absent from the CI report are unverified. */
export function reqStatusMap(s: Status): Map<string, ReqStatusEntry> {
  return new Map(s.requirements.items.map((i) => [i.id, { status: i.status, tests: i.tests ?? [] }]));
}

export function reqStatusOf(map: Map<string, ReqStatusEntry>, id: string): ReqStatus {
  return map.get(id)?.status ?? "unverified";
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
