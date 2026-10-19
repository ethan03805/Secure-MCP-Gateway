// Plain-language text for Gateway reason codes, from the message catalogue
// the console shares with the desktop application (docs/design/messages.json,
// SRS FR-20.48). The catalogue's reasonCodes are Appendix B Table B.2 word for
// word; a Go test keeps them equal to the error builder's messages.
import { reasonCodes } from "../../docs/design/messages.json";

type Entry = { codes: number[]; message: string };
const table: Record<string, Entry> = reasonCodes;

// reasonMessage returns the catalogue message for a reason code, with
// {correlationId} filled when known and {approvalUrl} pointing at the
// Approvals view, or undefined for a code the catalogue does not list (for
// example a filter's own reason code).
export function reasonMessage(code: string | undefined, correlationId?: string): string | undefined {
  if (!code) return undefined;
  const e = Object.prototype.hasOwnProperty.call(table, code) ? table[code] : undefined;
  if (!e) return undefined;
  return e.message
    .replaceAll("{approvalUrl}", "the Approvals view")
    .replaceAll("{correlationId}", correlationId ?? "of this call");
}
