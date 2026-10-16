import fs from "node:fs";
import path from "node:path";
import GithubSlugger from "github-slugger";
import { REPO_ROOT, readDoc } from "./content";
import { parseDiagram, type ParsedDiagram } from "./diagram";

export type Flow = {
  slug: string;
  title: string;
  /** Repository-relative source file. */
  file: string;
  /** "flow" for docs/flows/*.md, "architecture" for a diagram lifted from ArchitectureV2.md. */
  origin: "flow" | "architecture";
  /** Markdown to render: the whole flow document, or the architecture section around one diagram. */
  markdown: string;
  diagrams: ParsedDiagram[];
};

const FLOW_DIR = "docs/flows";
const MERMAID = /```mermaid\n([\s\S]*?)```/g;

function diagramsIn(md: string): ParsedDiagram[] {
  return Array.from(md.matchAll(MERMAID), (m) => parseDiagram(m[1]));
}

/**
 * docs/flows/*.md, sorted by file name. A missing or empty directory yields no
 * flows. SITE_FLOWS_DIR points at another directory, for testing the renderer.
 */
function flowDocs(): Flow[] {
  const dir = process.env.SITE_FLOWS_DIR?.trim() || path.join(REPO_ROOT, FLOW_DIR);
  let files: string[] = [];
  try {
    files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".md") && f.toLowerCase() !== "readme.md")
      .sort();
  } catch {
    return [];
  }
  return files.map((f) => {
    const md = fs.readFileSync(path.join(dir, f), "utf8");
    const title = (md.match(/^# (.+)$/m)?.[1] ?? f.replace(/\.md$/, "").replace(/[-_]/g, " ")).trim();
    return {
      slug: f.replace(/\.md$/, "").toLowerCase().replace(/[^a-z0-9-]+/g, "-"),
      title,
      file: `${FLOW_DIR}/${f}`,
      origin: "flow" as const,
      markdown: md,
      diagrams: diagramsIn(md),
    };
  });
}

/** Each Mermaid diagram in ArchitectureV2.md with the heading and text of the section that holds it. */
function architectureDiagrams(): Flow[] {
  const md = readDoc("ArchitectureV2.md");
  const lines = md.split("\n");
  const out: Flow[] = [];
  const slugger = new GithubSlugger();
  let heading = "";
  let headingLine = 0;
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.startsWith("```")) {
      if (!inFence && l.startsWith("```mermaid")) {
        // Section body from the heading to the end of this diagram.
        let end = i + 1;
        while (end < lines.length && !lines[end].startsWith("```")) end++;
        const body = lines.slice(headingLine + 1, end + 1).join("\n");
        const title = heading.replace(/^[\d.]+\s+/, "").replace(/[*`]/g, "");
        out.push({
          slug: `architecture-${slugger.slug(title)}`,
          title,
          file: "ArchitectureV2.md",
          origin: "architecture",
          markdown: `# ${title}\n\n${body}\n`,
          diagrams: diagramsIn(body),
        });
        // Text before the diagram belongs to this entry; the next diagram starts after it.
        headingLine = end;
        i = end;
        continue;
      }
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const h = l.match(/^#{2,4}\s+(.*)$/);
    if (h) {
      heading = h[1].trim();
      headingLine = i;
    }
  }
  return out;
}

let memo: Flow[] | null = null;

export function loadFlows(): Flow[] {
  if (!memo) memo = [...flowDocs(), ...architectureDiagrams()];
  return memo;
}

export function flowSourceDir(): string {
  return FLOW_DIR;
}
