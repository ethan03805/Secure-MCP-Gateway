# Bundled fonts

IBM Plex Sans and IBM Plex Mono for the desktop application's windows. They are copied into `dist/fonts/` at build time (`scripts/copy-static.mjs`), and the windows load them through `plex.css`. Nothing is fetched from a font service.

| File | Face | Source |
|---|---|---|
| `ibm-plex-sans-latin-400-normal.woff2` | IBM Plex Sans 400 | `@fontsource/ibm-plex-sans` 5.3.0 |
| `ibm-plex-sans-latin-600-normal.woff2` | IBM Plex Sans 600 | `@fontsource/ibm-plex-sans` 5.3.0 |
| `ibm-plex-mono-latin-400-normal.woff2` | IBM Plex Mono 400 | `@fontsource/ibm-plex-mono` 5.3.0 |
| `ibm-plex-mono-latin-500-normal.woff2` | IBM Plex Mono 500 | `@fontsource/ibm-plex-mono` 5.3.0 |

These are the same files the console bundles from the same packages (`console/package.json`), so the two surfaces use identical faces. SHA-256 sums are recorded in `test/fonts.test.ts`, which fails if a file changes.

License: SIL Open Font License 1.1, copyright IBM Corp. The license texts are `OFL-IBM-Plex-Sans.txt` and `OFL-IBM-Plex-Mono.txt`. Both are shipped with the application and are not modified. The fonts are not sold on their own and keep their reserved names.

To update: install the new `@fontsource` versions in `console/`, copy the four Latin `.woff2` files and both `LICENSE` files here, then update the version in this table and the sums in the test.
