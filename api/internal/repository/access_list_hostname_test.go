package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// accessListItemRead is the item read of GetByID and List, both of which
// must select hostname.
var accessListItemRead = "^" + regexp.QuoteMeta(`SELECT id, access_list_id, directive, address, COALESCE(description, '') AS description, sort_order, created_at, hostname
	FROM access_list_items WHERE access_list_id = $1
	ORDER BY sort_order, created_at`) + "$"

var accessListItemColumns = []string{"id", "access_list_id", "directive", "address", "description", "sort_order", "created_at", "hostname"}

// A domain rule is stored as the placeholder (deny, all, hostname) whatever
// the item's directive and address say, so the column's CHECK always takes
// it and a version without the column renders it "deny all". An address
// rule gets a NULL hostname. Reading the list back returns the name.
func TestAccessListStoresDomainRulesAsPlaceholders(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	repo := NewAccessListRepository(&database.DB{DB: db})
	const id = "0b5e0c3a-8f2d-4c1e-9a7b-6d5e4f3a2b1c"
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	insert := "^" + regexp.QuoteMeta(`INSERT INTO access_list_items (access_list_id, directive, address, description, sort_order, hostname)
		VALUES ($1, $2, $3, $4, $5, $6)`) + "$"

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO access_lists`).WithArgs("partners", "", true, false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	mock.ExpectExec(insert).WithArgs(id, "allow", "192.0.2.10", "office", 0, nil).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(insert).WithArgs(id, "deny", "all", "", 1, "partner.example.com").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(`FROM access_lists WHERE id = \$1`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "satisfy_any", "pass_auth", "created_at", "updated_at"}).
			AddRow(id, "partners", "", true, false, now, now))
	mock.ExpectQuery(accessListItemRead).WithArgs(id).
		WillReturnRows(sqlmock.NewRows(accessListItemColumns).
			AddRow("00000000-0000-0000-0000-0000000000b1", id, "allow", "192.0.2.10", "office", 0, now, nil).
			AddRow("00000000-0000-0000-0000-0000000000b2", id, "deny", "all", "", 1, now, "partner.example.com"))
	mock.ExpectQuery(`FROM access_list_auth_users`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash"}))

	list, err := repo.Create(context.Background(), &model.CreateAccessListRequest{Name: "partners", Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "192.0.2.10", Description: "office", SortOrder: 0},
		{Directive: "allow", Address: "partner.example.com", SortOrder: 1, Hostname: "partner.example.com"},
	}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(list.Items) != 2 || list.Items[0].Hostname != "" ||
		list.Items[1].Hostname != "partner.example.com" || list.Items[1].Directive != "deny" || list.Items[1].Address != "all" {
		t.Fatalf("items = %+v, want the address rule without a hostname and the domain rule as deny all partner.example.com", list.Items)
	}
}

// List reads the hostname of every item as GetByID does.
func TestAccessListListReadsHostnames(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	repo := NewAccessListRepository(&database.DB{DB: db})
	const id = "0b5e0c3a-8f2d-4c1e-9a7b-6d5e4f3a2b1c"
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM access_lists`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`FROM access_lists\s+ORDER BY created_at DESC`).WithArgs(20, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "satisfy_any", "pass_auth", "created_at", "updated_at"}).
			AddRow(id, "partners", "", true, false, now, now))
	mock.ExpectQuery(accessListItemRead).WithArgs(id).
		WillReturnRows(sqlmock.NewRows(accessListItemColumns).
			AddRow("00000000-0000-0000-0000-0000000000b2", id, "deny", "all", "", 0, now, "partner.example.com"))
	mock.ExpectQuery(`FROM access_list_auth_users`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash"}))

	lists, total, err := repo.List(context.Background(), 1, 20)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(lists) != 1 || len(lists[0].Items) != 1 || lists[0].Items[0].Hostname != "partner.example.com" {
		t.Fatalf("List = %+v (total %d), want one list whose rule has the hostname", lists, total)
	}
}
