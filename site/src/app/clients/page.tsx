import DocPage from "@/components/DocPage";
import { readDoc } from "@/lib/content";
import { chapter } from "@/lib/site";

export const metadata = { title: "Client compatibility" };

const CH = chapter("/clients/");

export default function ClientsPage() {
  const md = readDoc("Client-Compatibility-Brief.md");
  return (
    <DocPage file="Client-Compatibility-Brief.md" md={md} title="Client compatibility" chapter={CH.n}>
      <p>
        What the agent harnesses in front of the Gateway expect, checked against their primary documentation, and where
        the specification changes to meet them. Measured results against running clients are in{" "}
        <a href="/status/#agents">Status, real-agent compatibility</a>.
      </p>
    </DocPage>
  );
}
