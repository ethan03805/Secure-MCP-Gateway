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
for (const f of ["settings.html", "intro.html", "status.html", "setup.html", "clients.html", "updates.html", "style.css"]) {
  copyFileSync(join(root, "src", f), join(root, "dist", f));
}
// The bundled IBM Plex faces, their stylesheet and their licenses
// (src/fonts/README.md); style.css imports fonts/plex.css.
mkdirSync(join(root, "dist", "fonts"), { recursive: true });
for (const f of readdirSync(join(root, "src", "fonts"))) {
  if (/\.(woff2|css|txt)$/.test(f)) copyFileSync(join(root, "src", "fonts", f), join(root, "dist", "fonts", f));
}
const messages = JSON.parse(readFileSync(join(root, "..", "docs", "design", "messages.json"), "utf8"));
// The console window's error page runs no script, so its catalogue text is
// filled in here: {{CODE.part}} becomes the HTML-escaped part of that
// desktop error, with {url} as "The console's address" (the page cannot
// know the address). An unknown code or part stops the build.
const escape = (/** @type {string} */ s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const errorPage = readFileSync(join(root, "src", "error.html"), "utf8").replace(/\{\{([A-Z_]+)\.(title|what|why|todo)\}\}/g, (_, code, part) => {
  const text = messages.desktop.errors[code]?.[part];
  if (typeof text !== "string") throw new Error(`error.html: no ${part} for ${code} in docs/design/messages.json`);
  return escape(text.replace(/^The server at \{url\}/, "The console's address").replace(/\{url\}/g, "the console's address"));
});
if (/\{\{|\{[a-z]+\}/.test(errorPage)) throw new Error("error.html: a catalogue part was not filled in");
writeFileSync(join(root, "dist", "error.html"), errorPage);
writeFileSync(
  join(root, "dist", "catalogue.js"),
  `// Generated from docs/design/messages.json by scripts/copy-static.mjs.\nexport const catalogue = ${JSON.stringify({ desktop: messages.desktop })};\n`,
);
