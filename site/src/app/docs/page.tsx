import Link from "next/link";
import { DocHead } from "@/components/Sheet";
import { DOCS, docExists, docMtime, readDoc } from "@/lib/content";
import { buildCommit, chapter, plural } from "@/lib/site";

export const metadata = { title: "Documents" };

const CH = chapter("/docs/");

export default function DocsIndex() {
  const docs = DOCS.filter((d) => docExists(d.file)).map((d) => {
    const md = readDoc(d.file);
    return { ...d, words: md.split(/\s+/).filter(Boolean).length, mtime: docMtime(d.file) };
  });
  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Documents"
        left={["Secure MCP Gateway", "Source documents"]}
        right={[plural(docs.length, "document"), `site build ${buildCommit()}`]}
      >
        <p>The documents in the repository, rendered as written. The structured chapters are derived from these.</p>
      </DocHead>
      <div className="table-wrap wide">
        <table>
          <thead>
            <tr>
              <th scope="col">Document</th>
              <th scope="col">About</th>
              <th scope="col">File</th>
              <th scope="col" className="num">
                Words
              </th>
              <th scope="col" className="num">
                Changed
              </th>
            </tr>
          </thead>
          <tbody>
            {docs.map((d) => (
              <tr key={d.slug}>
                <td>
                  <Link href={`/docs/${d.slug}/`}>{d.title}</Link>
                </td>
                <td>{d.blurb}</td>
                <td className="id">{d.file}</td>
                <td className="num">{d.words.toLocaleString("en-US")}</td>
                <td className="num">{d.mtime}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}
