import type { ReactNode } from "react";
import Mermaid from "@/components/Mermaid";
import { DocHead } from "@/components/Sheet";
import { docMtime } from "@/lib/content";
import { renderMarkdown, toc } from "@/lib/markdown";
import { REPO_URL, buildCommit } from "@/lib/site";

/** A long-form document rendered as written, with a contents rail. */
export default async function DocPage({
  file,
  md,
  title,
  chapter,
  tocDepth = 3,
  left,
  children,
}: {
  file: string;
  md: string;
  title: string;
  chapter?: number;
  tocDepth?: number;
  left?: ReactNode[];
  children?: ReactNode;
}) {
  const html = await renderMarkdown(md, { dropTitle: true });
  const entries = toc(md, tocDepth);
  const hasDiagrams = md.includes("```mermaid");
  return (
    <div className="doc-layout">
      <nav className="toc" aria-label="Sections of this document">
        <ol>
          {entries.map((e) => (
            <li key={e.id} className={`d${e.depth}`}>
              <a href={`#${e.id}`}>{e.text}</a>
            </li>
          ))}
        </ol>
      </nav>
      <article className="prose">
        <DocHead
          chapter={chapter}
          title={title}
          left={[
            ...(left ?? []),
            <a key="f" href={`${REPO_URL}/blob/main/${file}`}>
              {file}
            </a>,
          ]}
          right={[`last changed ${docMtime(file)}`, `site build ${buildCommit()}`]}
        >
          {children}
        </DocHead>
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </article>
      {hasDiagrams && <Mermaid />}
    </div>
  );
}
