// Copies the static files of the bundled windows into dist/ beside the
// JavaScript tsc wrote there. Tauri packages dist/ (frontendDist).
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist"), { recursive: true });
for (const f of ["settings.html", "error.html", "style.css"]) {
  copyFileSync(join(root, "src", f), join(root, "dist", f));
}
