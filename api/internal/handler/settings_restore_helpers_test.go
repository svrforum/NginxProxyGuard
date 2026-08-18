package handler

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The API container runs with cap_drop ALL + cap_add DAC_OVERRIDE. It can write
// certs/default-selfsigned.{crt,key} (owned by the nginx container's uid 101)
// but cannot chmod them: that needs CAP_FOWNER, which is dropped. The old
// extract order opened the destination with O_TRUNC and returned the chmod
// error before copying a byte, so a restore left both files at 0 bytes and
// `nginx -t` failed for the whole proxy until the container restarted.
func TestRestoreFileAtomicKeepsDestinationWhenChmodFails(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "default-selfsigned.key")
	original := "-----BEGIN PRIVATE KEY-----\noriginal\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(dest, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	restore := forceChmodError(t, os.ErrPermission)
	defer restore()

	replacement := "restored-from-backup"
	err := restoreFileAtomic(strings.NewReader(replacement), dest, int64(len(replacement)))
	if err == nil {
		t.Fatal("expected the chmod failure to be reported, got nil")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected the underlying chmod error to be wrapped, got %v", err)
	}

	assertFileContent(t, dest, original)
	assertNoTempLeftovers(t, dir)
}

// Same failure, on the file whose truncation actually breaks nginx.
func TestRestoreFileAtomicKeepsDestinationWhenCopyFails(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "default-selfsigned.crt")
	original := "-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(dest, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	// header.Size says 64 bytes, the archive delivers 5: the size-mismatch
	// check must still fire, and must not have eaten the old certificate.
	if err := restoreFileAtomic(strings.NewReader("short"), dest, 64); err == nil {
		t.Fatal("expected a size mismatch error, got nil")
	}

	assertFileContent(t, dest, original)
	assertNoTempLeftovers(t, dir)
}

// The hardening that motivated the chmod in the first place must survive the
// fix: the restored file gets the policy mode, not the temp file's 0600 and not
// the archive header's mode.
func TestRestoreFileAtomicAppliesSecureModeOnOverwrite(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name     string
		wantMode os.FileMode
		// pre-existing mode, deliberately wrong in both directions
		oldMode os.FileMode
	}{
		{name: "default-selfsigned.key", wantMode: 0600, oldMode: 0644},
		{name: "default-selfsigned.crt", wantMode: 0644, oldMode: 0600},
		{name: "privkey.pem", wantMode: 0600, oldMode: 0666},
	}

	for _, tc := range cases {
		dest := filepath.Join(dir, tc.name)
		if err := os.WriteFile(dest, []byte("stale"), tc.oldMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dest, tc.oldMode); err != nil {
			t.Fatal(err)
		}

		content := "restored " + tc.name
		if err := restoreFileAtomic(strings.NewReader(content), dest, int64(len(content))); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		assertFileContent(t, dest, content)
		info, err := os.Stat(dest)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != tc.wantMode {
			t.Errorf("%s: mode = %#o, want %#o", tc.name, got, tc.wantMode)
		}
	}

	assertNoTempLeftovers(t, dir)
}

// A restore into a directory that does not exist yet (a new cert id) still
// works, and a symlinked destination is replaced by a regular file rather than
// followed.
func TestRestoreFileAtomicCreatesAndReplacesSymlink(t *testing.T) {
	dir := t.TempDir()

	nested := filepath.Join(dir, "8f1c", "fullchain.pem")
	content := "brand new"
	if err := restoreFileAtomic(strings.NewReader(content), nested, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, nested, content)

	outside := filepath.Join(dir, "outside.pem")
	if err := os.WriteFile(outside, []byte("must not be written through"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := restoreFileAtomic(strings.NewReader(content), link, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, link, content)
	assertFileContent(t, outside, "must not be written through")
	if info, err := os.Lstat(link); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Error("destination is still a symlink after restore")
	}
}

// The real production shape: a destination owned by another uid, in a directory
// this process may write. Only runs where chmod on a foreign-owned file
// actually fails (root without CAP_FOWNER, i.e. the container's capability
// set); it is skipped otherwise instead of pretending to have proven anything.
func TestRestoreFileAtomicOverForeignOwnedDestination(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a file owned by another uid")
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "default-selfsigned.crt")
	original := "-----BEGIN CERTIFICATE-----\nforeign\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(dest, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	const nginxUID = 101
	if err := os.Chown(dest, nginxUID, nginxUID); err != nil {
		t.Skipf("cannot chown the destination to uid %d: %v", nginxUID, err)
	}
	if err := os.Chmod(dest, 0644); err == nil {
		t.Skip("this process still holds CAP_FOWNER, so the production failure cannot occur here; run with --cap-drop=FOWNER")
	}

	content := "restored over a file we do not own"
	if err := restoreFileAtomic(strings.NewReader(content), dest, int64(len(content))); err != nil {
		t.Fatalf("restore over a foreign-owned destination failed: %v", err)
	}
	assertFileContent(t, dest, content)
	assertNoTempLeftovers(t, dir)
}

// extractFile still refuses anything outside /etc/nginx, and does so before
// touching the filesystem.
func TestExtractFileRejectsPathsOutsideNginxRoot(t *testing.T) {
	h := &SettingsHandler{}
	err := h.extractFile(nil, "/etc/passwd", nil)
	if err == nil || !strings.Contains(err.Error(), "path traversal blocked") {
		t.Fatalf("expected a path traversal error, got %v", err)
	}
}

func forceChmodError(t *testing.T, want error) func() {
	t.Helper()
	original := chmodFile
	chmodFile = func(*os.File, os.FileMode) error { return want }
	return func() { chmodFile = original }
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q (%d bytes), want %q (%d bytes)", path, got, len(got), want, len(want))
	}
}

func assertNoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".npg-restore-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
