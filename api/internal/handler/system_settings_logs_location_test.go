package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// Only raw log names resolve, and never through a symlink.
func TestLocalLogFilePathAcceptsOnlyRawLogFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"access_raw.log", "access_raw.log-20260919", "access_raw.log-20261009-000004.gz", "error_raw.log-20261009-120000", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "error_raw.log")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"access_raw.log", "access_raw.log-20260919", "access_raw.log-20261009-000004.gz", "error_raw.log-20261009-120000"} {
		if _, _, err := localLogFilePath(dir, name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"../x", "a/b", "photo.jpg", "notes.txt", "access_raw.log.part", "access_raw.log-20261009-000004.gz.part", "..", "/etc/passwd", "error_raw.log"} {
		if _, _, err := localLogFilePath(dir, name); !errors.Is(err, errLogFileName) {
			t.Errorf("%q must be refused as an invalid name, got %v", name, err)
		}
	}
	if _, _, err := localLogFilePath(dir, "access_raw.log-20200101-000000.gz"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing raw log must be not-found, got %v", err)
	}
}

func newLogFileRequest(method, target, filename string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	return c, rec
}

// The live files are refused by the server, not only hidden by the UI.
func TestDeleteRefusesTheActiveRawLogs(t *testing.T) {
	h := &SystemSettingsHandler{}
	for _, name := range []string{"access_raw.log", "error_raw.log"} {
		c, rec := newLogFileRequest(http.MethodDelete, "/api/v1/system-settings/log-files/"+name, name)
		if err := h.DeleteLogFile(c); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "active log file") {
			t.Errorf("DELETE %s = %d %s, want 400 active log file", name, rec.Code, rec.Body)
		}
	}
	c, rec := newLogFileRequest(http.MethodDelete, "/api/v1/system-settings/log-files/x", "../../etc/passwd")
	if err := h.DeleteLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("DELETE ../../etc/passwd = %d, want 400", rec.Code)
	}
}

func TestLastLinesKeepsTheEndAndCutsLongLines(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 2000; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	b.WriteString(strings.Repeat("y", viewMaxLineBytes*3) + "\n")
	b.WriteString("\nlast without newline")

	got, err := lastLines(strings.NewReader(b.String()), 4)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 4 || lines[0] != "line 2000" || len(lines[1]) != viewMaxLineBytes || lines[2] != "" || lines[3] != "last without newline" {
		t.Fatalf("unexpected tail: %d lines, first=%q second len=%d third=%q fourth=%q", len(lines), lines[0], len(lines[1]), lines[2], lines[3])
	}
	if got, _ := lastLines(strings.NewReader("a\nb\n"), 10); got != "a\nb\n" {
		t.Fatalf("fewer lines than asked: %q", got)
	}
}

func TestReadLogTailHandlesCompressedAndLargePlainFiles(t *testing.T) {
	dir := t.TempDir()

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	for i := 1; i <= 5000; i++ {
		fmt.Fprintf(zw, "gz %d\n", i)
	}
	zw.Close()
	gzPath := filepath.Join(dir, "access_raw.log-20261009-000000.gz")
	if err := os.WriteFile(gzPath, gz.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// A plain file larger than the preview window: only its end is read.
	plainPath := filepath.Join(dir, "access_raw.log")
	pf, err := os.Create(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	pf.Write(bytes.Repeat([]byte(strings.Repeat("z", 99)+"\n"), (viewPlainWindow/100)+5000))
	pf.WriteString("plain tail\n")
	pf.Close()

	for path, want := range map[string]string{gzPath: "gz 4999\ngz 5000\n", plainPath: strings.Repeat("z", 99) + "\nplain tail\n"} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := f.Stat()
		got, err := readLogTail(context.Background(), f, filepath.Base(path), info.Size(), 2)
		f.Close()
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", filepath.Base(path), got, err, want)
		}
	}

	// A request that has gone away stops a long decompression.
	f, _ := os.Open(gzPath)
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readLogTail(ctx, f, filepath.Base(gzPath), 0, 2); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled read: %v", err)
	}
}

func testArchiver(t *testing.T, mounted bool) (*service.RawLogArchiver, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "archive")
	if mounted {
		if err := os.MkdirAll(root, 0755); err != nil {
			t.Fatal(err)
		}
	}
	settings := &model.SystemSettings{ID: "test-instance", RawLogArchiveEnabled: true, RawLogArchiveRetentionDays: 365, RawLogCompressRotated: true}
	a := service.NewRawLogArchiver(root, t.TempDir(), 0, func(context.Context) (*model.SystemSettings, error) {
		s := *settings
		return &s, nil
	})
	return a, root
}

// The archive location answers with the archive's status when it cannot be
// used, and a bad location is refused.
func TestArchiveLocationAnswersWithTheArchiveStatus(t *testing.T) {
	h := &SystemSettingsHandler{}

	// No archiver wired.
	c, rec := newLogFileRequest(http.MethodDelete, "/x?location=archive", "access_raw.log-20261009-000000.gz")
	if err := h.DeleteLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("no archiver: %d %s", rec.Code, rec.Body)
	}

	// Not mounted: 409 carrying the status.
	a, _ := testArchiver(t, false)
	h.SetRawLogArchiver(a)
	c, rec = newLogFileRequest(http.MethodDelete, "/x?location=archive", "access_raw.log-20261009-000000.gz")
	if err := h.DeleteLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"status":"not_mounted"`) {
		t.Fatalf("not mounted: %d %s", rec.Code, rec.Body)
	}

	// Mounted but not initialised: deleting is a write, so it is refused.
	a, _ = testArchiver(t, true)
	h.SetRawLogArchiver(a)
	c, rec = newLogFileRequest(http.MethodDelete, "/x?location=archive", "access_raw.log-20261009-000000.gz")
	if err := h.DeleteLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"status":"not_initialized"`) {
		t.Fatalf("not initialised: %d %s", rec.Code, rec.Body)
	}

	// Names outside the archive's pattern never reach the filesystem.
	for _, name := range []string{"../x", "access_raw.log", ".npg-raw-log-archive"} {
		c, rec = newLogFileRequest(http.MethodGet, "/x?location=archive", name)
		if err := h.DownloadLogFile(c); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("download %q from the archive: %d", name, rec.Code)
		}
	}

	c, rec = newLogFileRequest(http.MethodGet, "/x?location=elsewhere", "access_raw.log")
	if err := h.ViewLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown location: %d", rec.Code)
	}
}

func TestArchiveFileDownloadAndPreview(t *testing.T) {
	a, root := testArchiver(t, true)
	if _, err := a.Initialise(context.Background()); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("first\nsecond\n"))
	zw.Close()
	name := "access_raw.log-20261009-000000.gz"
	if err := os.WriteFile(filepath.Join(root, name), gz.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	h := &SystemSettingsHandler{}
	h.SetRawLogArchiver(a)

	c, rec := newLogFileRequest(http.MethodGet, "/x?location=archive&lines=1", name)
	if err := h.ViewLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"content":"second\n"`) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}

	c, rec = newLogFileRequest(http.MethodGet, "/x?location=archive", name)
	if err := h.DownloadLogFile(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), gz.Bytes()) ||
		!strings.Contains(rec.Header().Get(echo.HeaderContentDisposition), name) {
		t.Fatalf("download: %d %q %d bytes", rec.Code, rec.Header().Get(echo.HeaderContentDisposition), rec.Body.Len())
	}
}
