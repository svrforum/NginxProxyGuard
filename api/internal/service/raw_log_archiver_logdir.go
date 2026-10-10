package service

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The archive must be a second home for the rotated raw logs, never a second
// name for the first one. leadsToLogDir catches the log directory, or one of
// its parents, by any path on the same filesystem: device and inode match.
// Another mount of it — an overlay with the log directory as a lower layer,
// an SMB or NFS share of the same folder, a FUSE view — has device and inode
// numbers of its own, and a file in it compares equal with the local one
// because it is the local one. Deleting the "moved" file then deletes the
// only copy. Two checks go by names instead:
//
//   - showsLogDir: Check, "Use this directory" and every pass create a file
//     under a new name in the log directory, look for it under the root (and
//     under root/<log directory name>), and remove it. Found: status log_dir.
//   - releaseLocal: before a local file is deleted it is renamed aside, under
//     a new name, and the archive's copy is checked once more. A root that
//     shows the log directory shows the renamed file as well, or loses the
//     "copy"; the file is renamed back and kept.
//
// The names are new on purpose: a network filesystem may answer a lookup of
// a name it has seen before from its cache, but has nothing cached for a
// name nobody has looked up yet.

// errArchiveShowsLogDir: a file set aside in the log directory showed up in
// the archive. The pass stops there; every other file would be the same.
var errArchiveShowsLogDir = errors.New("the archive directory shows the nginx log directory through another mount; the local file is kept")

// Prefixes of the files these checks keep in the log directory for a moment.
// Neither makes a raw log name, so no listing shows them and logrotate's
// patterns never match them.
const (
	logDirProbePrefix = ".npg-archive-probe-"
	setAsidePrefix    = ".npg-moving-"
)

// setAsideRE is a local file releaseLocal set aside: the prefix, 16 hex
// digits, a dash and the file's own name.
var setAsideRE = regexp.MustCompile(`^\.npg-moving-[0-9a-f]{16}-(.+)$`)

// uniqueSuffix is 16 random hex digits: part of a name nobody has looked up.
func uniqueSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// logDirDetail says why the root counts as the nginx log directory, or ""
// when it does not. probe runs the probe file check now; otherwise the last
// check's finding stands. Runs with the slot held.
func (a *RawLogArchiver) logDirDetail(root os.FileInfo, probe bool) string {
	if a.leadsToLogDir(root) {
		return fmt.Sprintf("%s is the nginx log directory %s (or one of its parents), so nothing there would leave the log disk: bind a directory on another disk or a NAS share to %s instead", a.root, a.localDir, a.root)
	}
	if probe {
		if shown, ok := a.showsLogDir(); ok {
			a.noteLogDirShown(shown)
		}
	}
	a.mu.Lock()
	shown := a.logDirShownAt
	a.mu.Unlock()
	if shown == "" {
		return ""
	}
	return fmt.Sprintf("%s shows the nginx log directory %s through another mount (a file created there appeared as %s), so nothing there would leave the log disk: bind a directory on another disk or a NAS share to %s instead", a.root, a.localDir, shown, a.root)
}

// noteLogDirShown records where a file of the log directory showed up under
// the root ("" for nowhere).
func (a *RawLogArchiver) noteLogDirShown(path string) {
	a.mu.Lock()
	a.logDirShownAt = path
	a.mu.Unlock()
}

// showsLogDir creates an empty file under a new name in the log directory,
// looks for it under the root and under root/<log directory name>, and
// removes it again. It returns where the file showed up, "" for nowhere. ok
// is false when the file could not be created (a read-only or full log
// directory): that says nothing, and releaseLocal still guards every
// deletion. Runs with the slot held, so a probe file found on entry was left
// by a process that stopped mid-check and is removed.
func (a *RawLogArchiver) showsLogDir() (shown string, ok bool) {
	dir := filepath.Clean(a.localDir)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), logDirProbePrefix) && e.Type().IsRegular() {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	suffix, err := uniqueSuffix()
	if err != nil {
		return "", false
	}
	name := logDirProbePrefix + suffix
	probe := filepath.Join(dir, name)
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", false
	}
	f.Close()
	defer os.Remove(probe)
	for _, p := range []string{filepath.Join(a.root, name), filepath.Join(a.root, filepath.Base(dir), name)} {
		if _, err := os.Lstat(p); err == nil {
			return p, true
		}
	}
	return "", true
}

// releaseLocal deletes the local file src once the archive holds its copy as
// final (size bytes; sum, when given, the SHA-256 of its content). src is
// renamed aside first, under a new name in the same directory, and deleted
// only when it is still the file that was copied (srcInfo), its new name does
// not show up in the archive, and final is still a separate regular file of
// that size (and content). Otherwise it is renamed back and kept.
func (a *RawLogArchiver) releaseLocal(src, final string, srcInfo os.FileInfo, size int64, sum []byte) error {
	name := filepath.Base(src)
	suffix, err := uniqueSuffix()
	if err != nil {
		return err
	}
	aside := filepath.Join(filepath.Dir(src), setAsidePrefix+suffix+"-"+name)
	if err := os.Rename(src, aside); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // gone already: nothing left to delete
		}
		return err
	}
	keep := func(cause error) error {
		if err := os.Rename(aside, src); err != nil {
			return fmt.Errorf("%w; the local file stays as %s until the next pass puts it back (%v)", cause, filepath.Base(aside), err)
		}
		return cause
	}
	if li, err := os.Lstat(aside); err != nil || !os.SameFile(srcInfo, li) { // both local: no other mount involved
		return keep(&errArchiveConflict{name: name, reason: conflictLocalChanged})
	}
	if shown := filepath.Join(a.root, filepath.Base(aside)); lstatFound(shown) {
		a.noteLogDirShown(shown)
		return keep(fmt.Errorf("%s: %w", name, errArchiveShowsLogDir))
	}
	fi, err := os.Lstat(final)
	ok := err == nil && fi.Mode().IsRegular() && fi.Size() == size && !a.sameFile(srcInfo, fi)
	if ok && sum != nil {
		got, err := fileSHA256(final)
		ok = err == nil && bytes.Equal(got, sum)
	}
	if !ok {
		return keep(&errArchiveConflict{name: name, reason: conflictCopyGone})
	}
	if err := os.Remove(aside); err != nil {
		return keep(err)
	}
	return nil
}

func lstatFound(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// restoreSetAside puts back the files a pass set aside and did not get to
// delete or rename back (the process stopped in between): under their own
// names they move like any other. Passes never overlap, and a name that is
// taken again is left alone.
func (a *RawLogArchiver) restoreSetAside() {
	entries, err := os.ReadDir(a.localDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		m := setAsideRE.FindStringSubmatch(e.Name())
		if m == nil || !IsArchivedRawLogName(m[1]) || !e.Type().IsRegular() {
			continue
		}
		orig := filepath.Join(a.localDir, m[1])
		if _, err := os.Lstat(orig); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := os.Rename(filepath.Join(a.localDir, e.Name()), orig); err != nil {
			log.Printf("[RawLogArchive] cannot put %s back as %s: %v", e.Name(), m[1], err)
		}
	}
}
