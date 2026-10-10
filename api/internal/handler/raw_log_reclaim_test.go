package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type fakeReclaimJob struct {
	startErr  error
	gotUser   string
	gotMax    *int
	started   bool
	refreshed bool
	stopped   bool
}

func (f *fakeReclaimJob) Status(_ context.Context, refresh bool) (*model.LogRawReclaimStatus, error) {
	f.refreshed = refresh
	return &model.LogRawReclaimStatus{Status: model.RawReclaimIdle, Supported: true}, nil
}

func (f *fakeReclaimJob) Start(_ context.Context, user string, maxChunks *int) (*model.LogRawReclaimStatus, error) {
	f.gotUser, f.gotMax = user, maxChunks
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.started = true
	return &model.LogRawReclaimStatus{Status: model.RawReclaimRunning, Supported: true}, nil
}

func (f *fakeReclaimJob) Stop(context.Context) (*model.LogRawReclaimStatus, error) {
	f.stopped = true
	return &model.LogRawReclaimStatus{Status: model.RawReclaimPaused, Supported: true}, nil
}

func callReclaim(t *testing.T, job *fakeReclaimJob, method, target, body string) (int, map[string]any) {
	t.Helper()
	h := &RawLogReclaimHandler{job: job}
	e := echo.New()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	var err error
	switch {
	case method == http.MethodGet:
		err = h.GetStatus(c)
	case strings.HasSuffix(target, "/start"):
		err = h.Start(c)
	default:
		err = h.Stop(c)
	}
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response %q: %v", rec.Body.String(), err)
	}
	return rec.Code, out
}

const reclaimBase = "/api/v1/system-settings/log-storage/raw-reclaim"

func TestRawLogReclaimStartAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		err    error
		status int
		code   string
	}{
		{"accepted without a body", "", nil, http.StatusAccepted, ""},
		{"accepted with max_chunks", `{"max_chunks":2}`, nil, http.StatusAccepted, ""},
		{"max_chunks below 1", `{"max_chunks":0}`, nil, http.StatusBadRequest, ""},
		{"max_chunks above the column", `{"max_chunks":3000000000}`, nil, http.StatusBadRequest, ""},
		{"already running", "", service.ErrRawReclaimRunning, http.StatusConflict, "already_running"},
		{"unsupported", "", &service.RawReclaimPreconditionError{Code: "unsupported", Reason: "catalog_changed"}, http.StatusPreconditionFailed, "unsupported"},
		{"free space unknown", "", &service.RawReclaimPreconditionError{Code: "free_space_unknown"}, http.StatusPreconditionFailed, "free_space_unknown"},
		{"insufficient space", "", &service.RawReclaimPreconditionError{Code: "insufficient_space", FreeBytes: 5, RequiredBytes: 7}, http.StatusPreconditionFailed, "insufficient_space"},
		{"database error", "", &pq.Error{Code: "XX000", Message: "secret detail"}, http.StatusInternalServerError, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := &fakeReclaimJob{startErr: tc.err}
			got, body := callReclaim(t, job, http.MethodPost, reclaimBase+"/start", tc.body)
			if got != tc.status {
				t.Fatalf("status %d, want %d (body %v)", got, tc.status, body)
			}
			if tc.code != "" && body["code"] != tc.code {
				t.Fatalf("code %v, want %s", body["code"], tc.code)
			}
			if strings.Contains(strings.ToLower(toString(body["error"])+" "+toString(body["details"])), "secret detail") {
				t.Fatalf("driver text reached the client: %v", body)
			}
			switch tc.name {
			case "accepted with max_chunks":
				if job.gotMax == nil || *job.gotMax != 2 || job.gotUser != "admin" {
					t.Fatalf("max %v user %q", job.gotMax, job.gotUser)
				}
			case "accepted without a body":
				if job.gotMax != nil || !job.started {
					t.Fatalf("max %v started %v", job.gotMax, job.started)
				}
			case "max_chunks below 1", "max_chunks above the column":
				if job.gotUser != "" {
					t.Fatal("the service was called for an invalid request")
				}
			case "unsupported":
				if body["reason"] != "catalog_changed" {
					t.Fatalf("reason %v", body["reason"])
				}
			case "insufficient space":
				if body["free_bytes"] != float64(5) || body["required_free_bytes"] != float64(7) {
					t.Fatalf("sizes %v", body)
				}
			}
		})
	}
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func TestRawLogReclaimStatusAndStop(t *testing.T) {
	job := &fakeReclaimJob{}
	if got, _ := callReclaim(t, job, http.MethodGet, reclaimBase, ""); got != http.StatusOK || job.refreshed {
		t.Fatalf("plain GET: %d, refreshed %v", got, job.refreshed)
	}
	if got, _ := callReclaim(t, job, http.MethodGet, reclaimBase+"?estimate=1", ""); got != http.StatusOK || !job.refreshed {
		t.Fatalf("estimate GET: %d, refreshed %v", got, job.refreshed)
	}
	got, body := callReclaim(t, job, http.MethodPost, reclaimBase+"/stop", "")
	if got != http.StatusOK || !job.stopped || body["status"] != model.RawReclaimPaused {
		t.Fatalf("stop: %d %v", got, body)
	}
}

// The schema generated clients read must list exactly what the API sends.
func TestSwaggerLogRawReclaimStatusMatchesTheModel(t *testing.T) {
	spec := string(swaggerYAML)
	for _, p := range []string{
		"\n  /system-settings/log-storage/raw-reclaim:\n",
		"\n  /system-settings/log-storage/raw-reclaim/start:\n",
		"\n  /system-settings/log-storage/raw-reclaim/stop:\n",
	} {
		if !strings.Contains(spec, p) {
			t.Errorf("swagger.yaml has no path %s", strings.TrimSpace(p))
		}
	}
	start := strings.Index(spec, "\n    LogRawReclaimStatus:\n")
	if start < 0 {
		t.Fatal("LogRawReclaimStatus schema not found in swagger.yaml")
	}
	block := spec[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[1:]); end != nil {
		block = block[:end[0]+1]
	}
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^        ([a-z_]+):$`).FindAllStringSubmatch(block, -1) {
		documented = append(documented, m[1])
	}
	var fields []string
	rt := reflect.TypeOf(model.LogRawReclaimStatus{})
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	sort.Strings(documented)
	sort.Strings(fields)
	if strings.Join(documented, ",") != strings.Join(fields, ",") {
		t.Fatalf("swagger LogRawReclaimStatus\n  %v\ndiffers from model.LogRawReclaimStatus\n  %v", documented, fields)
	}
}
