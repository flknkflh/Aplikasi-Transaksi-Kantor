//go:build !linux

package httpapi

// freeDiskBytes is only implemented on Linux (the deployment target); elsewhere
// the check is skipped and a full disk surfaces as a write error.
func freeDiskBytes(string) (uint64, bool) { return 0, false }
