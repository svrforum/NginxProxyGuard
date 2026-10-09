package handler

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

// Raw log file plumbing shared by the log file endpoints: name checks,
// paging and reading the tail of a (possibly compressed) file.

// Paging of GET /log-files. Without a limit every file is returned, as before
// the parameters existed; long retentions create tens of thousands of files,
// so the UI always pages.
const maxLogFilesLimit = 1000

type logFilesPage struct {
	limit  int // 0 = everything
	offset int
}

func parseLogFilesPage(c echo.Context) (logFilesPage, error) {
	var p logFilesPage
	if v := c.QueryParam("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLogFilesLimit {
			return p, errors.New("limit must be between 1 and 1000")
		}
		p.limit = n
	}
	if v := c.QueryParam("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, errors.New("offset must be 0 or more")
		}
		p.offset = n
	}
	return p, nil
}

func (p logFilesPage) apply(files []service.RawLogFile) []service.RawLogFile {
	if p.offset >= len(files) {
		return []service.RawLogFile{}
	}
	files = files[p.offset:]
	if p.limit > 0 && len(files) > p.limit {
		files = files[:p.limit]
	}
	return files
}

// errLogFileName is the answer for any name that is not a raw log file:
// path separators, "..", a .part file, anything else in the directory.
var errLogFileName = errors.New("invalid filename")

// localLogFilePath resolves a raw log file name in the local log directory
// and refuses symlinks (the directory once held /dev/stdout links).
func localLogFilePath(dir, name string) (string, os.FileInfo, error) {
	if !service.IsRawLogFileName(name) {
		return "", nil, errLogFileName
	}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, errLogFileName
	}
	return path, info, nil
}

// logFileError answers the errors of localLogFilePath and the archive lookups.
func logFileError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, errLogFileName):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": errLogFileName.Error()})
	case errors.Is(err, os.ErrNotExist):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "file not found"})
	}
	return directInternalError(c, err)
}

// Preview limits: a line longer than this is cut in the preview, and an
// uncompressed file is read only from this far before its end.
const (
	viewMaxLineBytes = 64 << 10
	viewPlainWindow  = 8 << 20
)

// ctxReader stops a long read (decompressing a large .gz) once the request
// is gone or past its deadline.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// readLogTail returns the last n lines of a raw log file. Compressed files
// (.gz, .bz2) are decompressed as a stream keeping only n lines; an
// uncompressed one — possibly a multi-gigabyte live file — is read only from
// its last viewPlainWindow bytes.
func readLogTail(ctx context.Context, f *os.File, name string, size int64, n int) (string, error) {
	switch {
	case strings.HasSuffix(name, ".gz"):
		zr, err := gzip.NewReader(ctxReader{ctx, bufio.NewReaderSize(f, 256<<10)})
		if err != nil {
			return "", err
		}
		defer zr.Close()
		return lastLines(ctxReader{ctx, zr}, n)
	case strings.HasSuffix(name, ".bz2"):
		return lastLines(ctxReader{ctx, bzip2.NewReader(bufio.NewReaderSize(f, 256<<10))}, n)
	}
	start := size - viewPlainWindow
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	buf, err := io.ReadAll(ctxReader{ctx, io.LimitReader(f, viewPlainWindow)})
	if err != nil {
		return "", err
	}
	if start > 0 {
		// The window starts mid-line; drop the fragment.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return lastLines(bytes.NewReader(buf), n)
}

// lastLines keeps the last n lines of r, each cut at viewMaxLineBytes.
func lastLines(r io.Reader, n int) (string, error) {
	if n < 1 {
		return "", nil
	}
	br := bufio.NewReaderSize(r, 64<<10)
	ring := make([][]byte, n)
	count := 0
	var cur []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if room := viewMaxLineBytes - len(cur); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			cur = append(cur, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(cur) > 0 {
			line := bytes.TrimRight(cur, "\n")
			ring[count%n] = append(ring[count%n][:0], line...)
			count++
			cur = cur[:0]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	var out strings.Builder
	first := 0
	if count > n {
		first = count - n
	}
	for i := first; i < count; i++ {
		out.Write(ring[i%n])
		out.WriteByte('\n')
	}
	return out.String(), nil
}
