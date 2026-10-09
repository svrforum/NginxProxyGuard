package repository

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/database"
)

// repoFuncSource returns the source text of the named function or method
// declared in fileName (go test runs in the package directory).
func repoFuncSource(t *testing.T, fileName, name string) string {
	t.Helper()
	src, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("read %s: %v", fileName, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", fileName, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return string(src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
		}
	}
	t.Fatalf("function %s not found in %s", name, fileName)
	return ""
}

// Log chunks are compressed after a day, and an autocomplete lookup that
// reaches a compressed day decompresses it on every keystroke. Every lookup
// must use the one 24-hour window.
func TestAutocompleteLookupsUseTheOneDayWindow(t *testing.T) {
	if autocompleteWindowSQL != `INTERVAL '24 hours'` {
		t.Fatalf("autocompleteWindowSQL = %s, want INTERVAL '24 hours'", autocompleteWindowSQL)
	}
	src, err := os.ReadFile("log_queries.go")
	if err != nil {
		t.Fatalf("read log_queries.go: %v", err)
	}
	if strings.Contains(string(src), "INTERVAL '7 days'") {
		t.Error("log_queries.go still reads a 7-day window")
	}
	for _, fn := range []string{"GetDistinctHosts", "GetDistinctIPs", "GetDistinctUserAgents", "GetDistinctCountries", "GetDistinctURIs", "GetDistinctMethods"} {
		body := repoFuncSource(t, "log_queries.go", fn)
		if !strings.Contains(body, "created_at >= NOW() - ` + autocompleteWindowSQL") {
			t.Errorf("%s does not bound created_at by autocompleteWindowSQL", fn)
		}
	}
	// The host search must collect the hosts before filtering them; inlined,
	// the ILIKE lands inside the skip scan and walks every row in the window.
	if !strings.Contains(repoFuncSource(t, "log_queries.go", "GetDistinctHosts"), "WITH hosts AS MATERIALIZED") {
		t.Error("GetDistinctHosts no longer searches a MATERIALIZED list of hosts")
	}
}

// The MATERIALIZED rewrite of the host search must answer exactly what the
// single query did: the same hosts, in the same order, under the same limit,
// with rows older than the window left out.
func TestGetDistinctHostsSearchMatchesTheSingleQuery(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE logs_partitioned (host text, created_at timestamptz NOT NULL DEFAULT now())`,
		`INSERT INTO logs_partitioned (host, created_at) VALUES
			('blog.example.com', now() - interval '1 hour'),
			('blog.example.com', now() - interval '2 hours'),
			('shop.example.com', now() - interval '2 hours'),
			('BLOG2.example.org', now() - interval '3 hours'),
			('my-blog.example.net', now() - interval '23 hours'),
			('oldblog.example.com', now() - interval '3 days'),
			('', now()),
			(NULL, now())`,
	)
	repo := &LogRepository{db: &database.DB{DB: db}}
	ctx := context.Background()

	single := func(search string, limit int) []string {
		t.Helper()
		rows, err := db.Query(`
			SELECT DISTINCT host FROM logs_partitioned
			WHERE host IS NOT NULL AND host != ''
			  AND created_at >= NOW() - `+autocompleteWindowSQL+`
			  AND host ILIKE $1 ORDER BY host LIMIT $2`, "%"+search+"%", limit)
		if err != nil {
			t.Fatalf("single query: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, h)
		}
		return out
	}

	for _, tc := range []struct {
		search string
		limit  int
		want   []string // as a set; the order is compared with the single query
	}{
		{"blog", 20, []string{"BLOG2.example.org", "blog.example.com", "my-blog.example.net"}},
		{"EXAMPLE", 2, nil},
		{"nothing-matches", 20, nil},
	} {
		got, err := repo.GetDistinctHosts(ctx, tc.search, tc.limit)
		if err != nil {
			t.Fatalf("GetDistinctHosts(%q): %v", tc.search, err)
		}
		if want := single(tc.search, tc.limit); !reflect.DeepEqual(got, want) {
			t.Errorf("GetDistinctHosts(%q, %d) = %v, the single query gives %v", tc.search, tc.limit, got, want)
		}
		if tc.want != nil {
			set := append([]string(nil), got...)
			sort.Strings(set)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(set, want) {
				t.Errorf("GetDistinctHosts(%q) = %v, want %v (hosts older than the window left out)", tc.search, got, tc.want)
			}
		}
		if tc.search == "EXAMPLE" && len(got) != 2 {
			t.Errorf("GetDistinctHosts(%q, 2) returned %d hosts, want the limit of 2", tc.search, len(got))
		}
	}
}
