// Copies the static files of the bundled windows into dist/ beside the
// JavaScript tsc wrote there, and writes dist/catalogue.js from the shared
// message catalogue docs/design/messages.json (SRS FR-20.48), so the
// windows carry its text from build time and never fetch it. Tauri
// packages dist/ (frontendDist).
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist"), { recursive: true });
for (const f of ["settings.html", "error.html", "intro.html", "status.html", "setup.html", "style.css"]) {
  copyFileSync(join(root, "src", f), join(root, "dist", f));
}
const messages = JSON.parse(readFileSync(join(root, "..", "docs", "design", "messages.json"), "utf8"));
writeFileSync(
  join(root, "dist", "catalogue.js"),
  `// Generated from docs/design/messages.json by scripts/copy-static.mjs.\nexport const catalogue = ${JSON.stringify({ desktop: messages.desktop })};\n`,
);
