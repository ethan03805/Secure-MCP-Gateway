import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

/** Repository root: the site lives in <repo>/site and reads the documents beside it. */
export const REPO_ROOT = path.resolve(process.cwd(), "..");

export function readDoc(relPath: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), "utf8");
}

export function docExists(relPath: string): boolean {
  return fs.existsSync(path.join(REPO_ROOT, relPath));
}

const mtimes = new Map<string, string>();

/**
 * Date of the last commit that touched a file. A fresh checkout gives every
 * file the same modification time, so git history is the reliable source;
 * the file system date is the fallback when history is unavailable.
 */
export function docMtime(relPath: string): string {
  const hit = mtimes.get(relPath);
  if (hit) return hit;
  let date = "";
  try {
    date = execFileSync("git", ["log", "-1", "--format=%cs", "--", relPath], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    date = "";
  }
  if (!date) date = fs.statSync(path.join(REPO_ROOT, relPath)).mtime.toISOString().slice(0, 10);
  mtimes.set(relPath, date);
  return date;
}

/** Documents the site renders as long-form pages. */
export const DOCS: { slug: string; file: string; title: string; blurb: string }[] = [
  {
    slug: "architecture-v2",
    file: "ArchitectureV2.md",
    title: "Architecture",
    blurb: "Logical decomposition into subsystems, elements, functions, interfaces and data stores.",
  },
  {
    slug: "problem-space",
    file: "architecture.md",
    title: "Architecture 2.0, problem space",
    blurb: "Threats, Neo4j Community Edition limits, protocol pitfalls, race control and the engineering server catalog.",
  },
  {
    slug: "security-controls",
    file: "MCP_Gateway_Security_SRS.md",
    title: "Security-control SRS V1",
    blurb: "The hierarchical security controls that parent every security requirement.",
  },
  {
    slug: "implementation-srs",
    file: "Secure_MCP_Gateway_SRS.md",
    title: "Implementation SRS",
    blurb: "Generated coding baseline: every requirement allocated to the architecture.",
  },
  {
    slug: "client-compatibility",
    file: "Client-Compatibility-Brief.md",
    title: "Client compatibility brief",
    blurb: "What Claude Code, Codex and Hermes expect today and where the specification must bend.",
  },
  {
    slug: "research-brief",
    file: "Secure-MCP-Gateway-Research-Brief.md",
    title: "Research brief",
    blurb: "The original survey of gateways, policy engines, audit stacks, secrets tools and filters.",
  },
  {
    slug: "documentation",
    file: "docs/README.md",
    title: "Documentation index",
    blurb: "Every user and operator document, runbook, control API reference and data file.",
  },
  {
    slug: "install",
    file: "docs/install.md",
    title: "Install guide",
    blurb: "install.sh, Homebrew, building from source, the Linux enforced host, upgrade, rollback and removal.",
  },
  {
    slug: "quickstart",
    file: "docs/quickstart.md",
    title: "Quick start",
    blurb: "Bootstrap an instance, connect Claude Code or Codex, make and approve a call, verify the journal.",
  },
  {
    slug: "operator-guide",
    file: "docs/operator-guide.md",
    title: "Operator guide",
    blurb: "Accounts, approvals, sessions, policy, packages, secrets, emergency stop, backups, keys, upgrades, remote access.",
  },
  {
    slug: "policy-reference",
    file: "docs/policy-reference.md",
    title: "Policy reference",
    blurb: "The policy document, evaluation, taint, rates and quotas, and the signed Policy Store.",
  },
  {
    slug: "packaging-guide",
    file: "docs/packaging-guide.md",
    title: "Packaging guide",
    blurb: "Build, sign, verify, import, enable and revoke server packages.",
  },
  {
    slug: "security-limitations",
    file: "docs/security-limitations.md",
    title: "Security limitations",
    blurb: "What the Gateway does not protect against, and why.",
  },
  {
    slug: "troubleshooting",
    file: "docs/troubleshooting.md",
    title: "Troubleshooting and reason codes",
    blurb: "Every error and reason code with its meaning and the next action.",
  },
  {
    slug: "changelog",
    file: "CHANGELOG.md",
    title: "Changelog",
    blurb: "Baseline history and the revision procedure.",
  },
  {
    slug: "floorplan",
    file: "FloorPlan.md",
    title: "Repository floor plan",
    blurb: "What each file in the repository is for.",
  },
];
