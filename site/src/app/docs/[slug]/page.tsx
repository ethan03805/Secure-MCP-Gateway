import Link from "next/link";
import { notFound } from "next/navigation";
import DocPage from "@/components/DocPage";
import { DOCS, docExists, readDoc } from "@/lib/content";
import { chapter } from "@/lib/site";

const CH = chapter("/docs/");

export function generateStaticParams() {
  return DOCS.filter((d) => docExists(d.file)).map((d) => ({ slug: d.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const d = DOCS.find((x) => x.slug === slug);
  return { title: d ? d.title : "Document" };
}

export default async function Doc({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const d = DOCS.find((x) => x.slug === slug);
  if (!d || !docExists(d.file)) notFound();
  const md = readDoc(d.file);
  const title = (md.match(/^# (.*)$/m) ?? ["", d.title])[1];
  return (
    <DocPage
      file={d.file}
      md={md}
      title={title}
      tocDepth={2}
      left={[
        <Link key="c" href="/docs/">
          {CH.n} Documents
        </Link>,
      ]}
    />
  );
}
