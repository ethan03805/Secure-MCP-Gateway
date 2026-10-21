package config

// ContextForge configures the ContextForge Connector (E-36, SRS FR-22,
// planned for v1.3.0; docs/contextforge.md).
type ContextForge struct {
	// Bundled runs the bundled ContextForge instance (FR-22.22). The
	// default is false: hosted-entry imports and hosted packages are then
	// refused with CONTEXTFORGE_DISABLED, and local-entry imports work.
	Bundled bool `toml:"bundled" json:"bundled"`
	// CatalogFile is an operator-supplied catalog read instead of the
	// pinned one; CatalogSHA256 is the digest the operator confirmed
	// (FR-22.1). The schema requires both or neither.
	CatalogFile   string `toml:"catalog_file" json:"catalog_file,omitempty"`
	CatalogSHA256 string `toml:"catalog_sha256" json:"catalog_sha256,omitempty"`
	// NPMRegistry and PyPIIndex are the registries a local-entry import
	// fetches the operator-pinned artifact from (default the public ones).
	NPMRegistry string `toml:"npm_registry" json:"npm_registry,omitempty"`
	PyPIIndex   string `toml:"pypi_index" json:"pypi_index,omitempty"`
	// Engine is the container engine (podman or docker) that runs the
	// bundled instance; default: podman, else docker, from PATH.
	Engine string `toml:"engine" json:"engine,omitempty"`
	// Cosign verifies the image signature (FR-22.19); default from PATH.
	Cosign string `toml:"cosign" json:"cosign,omitempty"`
	// Python is a CPython interpreter of the release lock's version
	// (3.12) from which the Connector creates the private virtual
	// environment of the managed-process form (FR-22.20, FR-22.25):
	// always on Windows, and where no container engine is installed.
	Python string `toml:"python" json:"python,omitempty"`
	// WheelDir is a directory holding exactly the release lock's wheel
	// set for this platform, installed instead of fetching the wheels from
	// their PyPI URLs (FR-22.20).
	WheelDir string `toml:"wheel_dir" json:"wheel_dir,omitempty"`
}
