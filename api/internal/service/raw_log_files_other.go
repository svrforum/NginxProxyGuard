//go:build !linux

package service

import (
	"os"
	"time"
)

// changeTime falls back to the modification time outside Linux. The API only
// ships for Linux.
func changeTime(info os.FileInfo) time.Time { return info.ModTime() }
