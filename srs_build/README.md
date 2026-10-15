# SRS build sources

`Secure_MCP_Gateway_SRS.md` is generated from these files. Edit the sources here, not the generated SRS.

| File | Contents |
|---|---|
| `front.md` | Document control, purpose, conventions, technology stack (Sections 1–3) |
| `req1.txt` … `req4.txt` | Functional requirements FR-1 … FR-12 |
| `req5.txt` | Security requirements (SR) and SEC dispositions (`@DISP`) |
| `appendix.md` | Appendices A–D (controlled parameters, error codes, roles, graph model) |
| `gen.py` | Validator and generator; also produces Appendices E–I |

Record format: `@ID | Title`, then `P:` parent, `S:` statement, `A:` allocation (`;`-separated E/F/X/I/D IDs), `V:` `Method | statement`, `SRC:` sources, `R:` rationale, followed by a blank line.

Build (from the project directory):

```
python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error and prints warnings for coverage gaps against `ArchitectureV2.md` and `MCP_Gateway_Security_SRS.md`.
