package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

type AccessListRepository struct {
	db *database.DB
}

func NewAccessListRepository(db *database.DB) *AccessListRepository {
	return &AccessListRepository{db: db}
}

func (r *AccessListRepository) Create(ctx context.Context, req *model.CreateAccessListRequest) (*model.AccessList, error) {
	satisfyAny := true
	if req.SatisfyAny != nil {
		satisfyAny = *req.SatisfyAny
	}
	passAuth := false
	if req.PassAuth != nil {
		passAuth = *req.PassAuth
	}

	// The list and its items are written in one transaction, so a failed
	// item leaves no list behind.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO access_lists (name, description, satisfy_any, pass_auth)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, req.Name, req.Description, satisfyAny, passAuth).Scan(&id); err != nil {
		return nil, err
	}
	if err := insertAccessListItems(ctx, tx, id, req.Items); err != nil {
		return nil, err
	}
	if err := insertAccessListAuthUsers(ctx, tx, id, req.AuthUsers); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit access list: %w", err)
	}

	return r.GetByID(ctx, id)
}

// insertAccessListItems writes items as the items of list listID, in tx. A
// domain rule (Hostname set, #320) is written as the placeholder (deny, all,
// hostname) whatever its Directive and Address say: the column's CHECK takes
// only that shape, and a version that does not know the column renders the
// row as "deny all", closed.
func insertAccessListItems(ctx context.Context, tx *sql.Tx, listID string, items []model.CreateAccessListItemRequest) error {
	for _, item := range items {
		directive, address := item.Directive, item.Address
		var hostname sql.NullString
		if item.Hostname != "" {
			directive, address = "deny", "all"
			hostname = sql.NullString{String: item.Hostname, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO access_list_items (access_list_id, directive, address, description, sort_order, hostname)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, listID, directive, address, item.Description, item.SortOrder, hostname); err != nil {
			return err
		}
	}
	return nil
}

func (r *AccessListRepository) GetByID(ctx context.Context, id string) (*model.AccessList, error) {
	var list model.AccessList
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, COALESCE(description, '') AS description, satisfy_any, pass_auth, created_at, updated_at
		FROM access_lists WHERE id = $1
	`, id).Scan(&list.ID, &list.Name, &list.Description, &list.SatisfyAny, &list.PassAuth, &list.CreatedAt, &list.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Get items
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, access_list_id, directive, address, COALESCE(description, '') AS description, sort_order, created_at, hostname
		FROM access_list_items WHERE access_list_id = $1
		ORDER BY sort_order, created_at
	`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item model.AccessListItem
		var hostname sql.NullString
		if err := rows.Scan(&item.ID, &item.AccessListID, &item.Directive, &item.Address, &item.Description, &item.SortOrder, &item.CreatedAt, &hostname); err != nil {
			return nil, err
		}
		item.Hostname = hostname.String
		list.Items = append(list.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate access list items: %w", err)
	}
	if list.AuthUsers, err = r.accessListAuthUsers(ctx, id); err != nil {
		return nil, err
	}

	return &list, nil
}

func (r *AccessListRepository) List(ctx context.Context, page, perPage int) ([]model.AccessList, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_lists`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, COALESCE(description, '') AS description, satisfy_any, pass_auth, created_at, updated_at
		FROM access_lists
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var lists []model.AccessList
	for rows.Next() {
		var list model.AccessList
		if err := rows.Scan(&list.ID, &list.Name, &list.Description, &list.SatisfyAny, &list.PassAuth, &list.CreatedAt, &list.UpdatedAt); err != nil {
			return nil, 0, err
		}
		lists = append(lists, list)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate access lists: %w", err)
	}

	// Get items for each list
	for i := range lists {
		itemRows, err := r.db.QueryContext(ctx, `
			SELECT id, access_list_id, directive, address, COALESCE(description, '') AS description, sort_order, created_at, hostname
			FROM access_list_items WHERE access_list_id = $1
			ORDER BY sort_order, created_at
		`, lists[i].ID)
		if err != nil {
			return nil, 0, err
		}
		for itemRows.Next() {
			var item model.AccessListItem
			var hostname sql.NullString
			if err := itemRows.Scan(&item.ID, &item.AccessListID, &item.Directive, &item.Address, &item.Description, &item.SortOrder, &item.CreatedAt, &hostname); err != nil {
				itemRows.Close()
				return nil, 0, err
			}
			item.Hostname = hostname.String
			lists[i].Items = append(lists[i].Items, item)
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return nil, 0, fmt.Errorf("failed to iterate access list items: %w", err)
		}
		itemRows.Close()
		if lists[i].AuthUsers, err = r.accessListAuthUsers(ctx, lists[i].ID); err != nil {
			return nil, 0, err
		}
	}

	return lists, total, nil
}

func (r *AccessListRepository) Update(ctx context.Context, id string, req *model.UpdateAccessListRequest) (*model.AccessList, error) {
	// Check if exists
	existing, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}

	// Build update query
	query := "UPDATE access_lists SET updated_at = $1"
	args := []interface{}{time.Now()}
	argIndex := 2

	if req.Name != nil {
		query += ", name = $" + strconv.Itoa(argIndex)
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Description != nil {
		query += ", description = $" + strconv.Itoa(argIndex)
		args = append(args, *req.Description)
		argIndex++
	}
	if req.SatisfyAny != nil {
		query += ", satisfy_any = $" + strconv.Itoa(argIndex)
		args = append(args, *req.SatisfyAny)
		argIndex++
	}
	if req.PassAuth != nil {
		query += ", pass_auth = $" + strconv.Itoa(argIndex)
		args = append(args, *req.PassAuth)
		argIndex++
	}

	query += " WHERE id = $" + strconv.Itoa(argIndex)
	args = append(args, id)

	// The list's fields and its items change in one transaction: if an
	// item fails, the list keeps its previous fields and items.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return nil, err
	}
	if req.Items != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_list_items WHERE access_list_id = $1`, id); err != nil {
			return nil, err
		}
		if err := insertAccessListItems(ctx, tx, id, req.Items); err != nil {
			return nil, err
		}
	}
	if req.AuthUsers != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_list_auth_users WHERE access_list_id = $1`, id); err != nil {
			return nil, err
		}
		if err := insertAccessListAuthUsers(ctx, tx, id, req.AuthUsers); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit access list: %w", err)
	}

	return r.GetByID(ctx, id)
}

func (r *AccessListRepository) Delete(ctx context.Context, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Clear references first: proxy_hosts.access_list_id has no FK constraint,
	// so deleting the list alone would leave dangling IDs that silently drop
	// the access restriction at the next config generation.
	if _, err := tx.ExecContext(ctx, `UPDATE proxy_hosts SET access_list_id = NULL WHERE access_list_id = $1`, id); err != nil {
		return fmt.Errorf("failed to detach access list from proxy hosts: %w", err)
	}

	// Items will be deleted by CASCADE
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_lists WHERE id = $1`, id); err != nil {
		return err
	}

	return tx.Commit()
}
