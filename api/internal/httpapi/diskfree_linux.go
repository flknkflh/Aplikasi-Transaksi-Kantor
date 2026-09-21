//go:build linux

package httpapi

import "syscall"

// freeDiskBytes reports the space available to unprivileged writers under dir.
func freeDiskBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
