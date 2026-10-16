# Server packaging and admission

How an operator admits a local MCP server without an external curation system (FR-14, SR-3-1 to SR-3.10-1, SR-3.5-1, SR-5.9-2; ARCH §18.1). Packaging is the only step that contacts a package registry.

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator
  participant PK as smcpctl package (F-96)
  participant R as Package registry (X-17)
  participant S as Candidate server (throwaway run)
  participant L as Library directory
  participant E13 as E-13 Trust Verifier
  participant E22 as E-22 Trust anchors
  participant E14 as E-14 Registry
  participant E24 as E-24 Console or CLI
  participant E21 as E-21 Journal

  O->>PK: package build with type, name, exact version, digest, classification
  PK->>PK: refuse ranges, dist-tags and missing digests
  PK->>R: fetch artifact
  R-->>PK: tarball, wheel, image or binary
  PK->>PK: verify digest, store under SHA-256
  PK->>S: start once, empty directory, no secrets, no network (Enforced)
  PK->>S: era probe, then tools/list
  S-->>PK: tools
  PK->>PK: write manifest.json (Appendix J) and provenance.json
  O->>PK: package sign with minisign key from file or prompt
  PK->>L: index.json, index.json.minisig, manifest, provenance, artifact
  E13->>L: scan library (interval or on command)
  E13->>E22: anchor for the signer, scope includes the risk class?
  E13->>E13: verify signature, digests, schema, provenance, revocations, metadata rule set
  E13->>E14: register immutable revision as verified-disabled
  E13->>E21: import receipt event
  O->>E24: enable revision (Administrator)
  E24->>E14: verified-disabled to enabled
  E14->>E21: enablement event
  Note over E14: Standalone profile: a high risk class is refused at this step (SR-4-1)
  Note over E14: At each launch E-13 re-verifies the artifact digest (SR-3-2). A changed tool list at run time suspends the revision (SR-3.8-1)
```

## Implementation as of commit a3193a5

Not implemented. Servers are configured as commands in `smcp.toml`; `internal/backend` starts each one and reads its live tool list at startup. The example written by `smcpctl bootstrap` launches the filesystem server through `npx`, which FR-14.10 and SR-3.6-1 forbid once packaging exists.
