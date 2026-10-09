//go:build !linux

package service

import "errors"

// statfsPath exists so the package builds on a developer's non-Linux machine.
// The API only ships for Linux.
func statfsPath(string) (rawStatfs, error) {
	return rawStatfs{}, errors.New("statfs is only implemented on Linux")
}

// fsTypeName knows no magic numbers outside Linux.
func fsTypeName(int64) string { return "" }
