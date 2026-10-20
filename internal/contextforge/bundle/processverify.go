package bundle

// ManagedPlatform is the platform name of the managed-process form in
// verification records and evidence; the record's WheelPlatform names the
// wheel set (wheels.go).
const ManagedPlatform = "managed-process"

// ReasonVersionMismatch: the installed virtual environment holds another
// ContextForge release than the release lock pins.
const ReasonVersionMismatch = "CONTEXTFORGE_VERSION_MISMATCH"
