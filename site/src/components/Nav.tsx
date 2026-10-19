import Link from "next/link";
import { CHAPTERS, START_HERE } from "@/lib/site";
import NavCurrent from "./NavCurrent";

export default function Nav({ commit, sample }: { commit: string; sample: boolean }) {
  return (
    <header className="masthead">
      <div className="masthead-row">
        <Link href="/" className="wordmark">
          Secure MCP Gateway
        </Link>
        <p className="masthead-meta">
          {sample ? <span className="flag-sample">sample data</span> : null}
          <span>build {commit}</span>
        </p>
      </div>
      <nav aria-label="Chapters" className="chapters">
        <ol>
          <li className="start-here">
            <Link href={START_HERE.href} data-href={START_HERE.href}>
              {START_HERE.label}
            </Link>
          </li>
          {CHAPTERS.map((c) => (
            <li key={c.href}>
              <Link href={c.href} data-href={c.href}>
                <span className="chno">{c.n}</span>
                {c.label}
              </Link>
            </li>
          ))}
        </ol>
      </nav>
      <NavCurrent />
    </header>
  );
}
