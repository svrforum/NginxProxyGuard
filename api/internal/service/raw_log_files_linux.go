//go:build linux

package service

import (
	"os"
	"syscall"
	"time"
)

// changeTime is the inode change time (ctime): the last write, rename or
// metadata change. gzip copies the original's modification time onto the
// .gz it writes, so only ctime tells how long ago compression finished.
func changeTime(info os.FileInfo) time.Time {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	}
	return info.ModTime()
}
