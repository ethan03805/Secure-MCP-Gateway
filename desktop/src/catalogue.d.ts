// scripts/copy-static.mjs writes dist/catalogue.js from
// docs/design/messages.json at build time (FR-20.48): the bundled windows
// carry the catalogue's text, and no window fetches it.
import type { Catalogue } from "./status-model.ts";

export declare const catalogue: Catalogue;
