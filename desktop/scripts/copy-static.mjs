// Copies the static files of the bundled windows into dist/ beside the
// JavaScript tsc wrote there, and writes dist/catalogue.js from the shared
// message catalogue docs/design/messages.json (SRS FR-20.48), so the
// windows carry its text from build time and never fetch it. Tauri
// packages dist/ (frontendDist).
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist"), { recursive: true });
for (const f of ["settings.html", "error.html", "intro.html", "status.html", "setup.html", "clients.html", "updates.html", "style.css"]) {
  copyFileSync(join(root, "src", f), join(root, "dist", f));
}
// The bundled IBM Plex faces, their stylesheet and their licenses
// (src/fonts/README.md); style.css imports fonts/plex.css.
mkdirSync(join(root, "dist", "fonts"), { recursive: true });
for (const f of readdirSync(join(root, "src", "fonts"))) {
  if (/\.(woff2|css|txt)$/.test(f)) copyFileSync(join(root, "src", "fonts", f), join(root, "dist", "fonts", f));
}
const messages = JSON.parse(readFileSync(join(root, "..", "docs", "design", "messages.json"), "utf8"));
writeFileSync(
  join(root, "dist", "catalogue.js"),
  `// Generated from docs/design/messages.json by scripts/copy-static.mjs.\nexport const catalogue = ${JSON.stringify({ desktop: messages.desktop })};\n`,
);
