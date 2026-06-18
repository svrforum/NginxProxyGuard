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

	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO access_lists (name, description, satisfy_any, pass_auth)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, req.Name, req.Description, satisfyAny, passAuth).Scan(&id)
	if err != nil {
		return nil, err
	}

	// Create items if provided
	for _, item := range req.Items {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO access_list_items (access_list_id, directive, address, description, sort_order)
			VALUES ($1, $2, $3, $4, $5)
		`, id, item.Directive, item.Address, item.Description, item.SortOrder)
		if err != nil {
			return nil, err
		}
	}

	return r.GetByID(ctx, id)
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
		SELECT id, access_list_id, directive, address, COALESCE(description, '') AS description, sort_order, created_at
		FROM access_list_items WHERE access_list_id = $1
		ORDER BY sort_order, created_at
	`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item model.AccessListItem
		if err := rows.Scan(&item.ID, &item.AccessListID, &item.Directive, &item.Address, &item.Description, &item.SortOrder, &item.CreatedAt); err != nil {
			return nil, err
		}
		list.Items = append(list.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate access list items: %w", err)
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
			SELECT id, access_list_id, directive, address, COALESCE(description, '') AS description, sort_order, created_at
			FROM access_list_items WHERE access_list_id = $1
			ORDER BY sort_order, created_at
		`, lists[i].ID)
		if err != nil {
			return nil, 0, err
		}
		for itemRows.Next() {
			var item model.AccessListItem
			if err := itemRows.Scan(&item.ID, &item.AccessListID, &item.Directive, &item.Address, &item.Description, &item.SortOrder, &item.CreatedAt); err != nil {
				itemRows.Close()
				return nil, 0, err
			}
			lists[i].Items = append(lists[i].Items, item)
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return nil, 0, fmt.Errorf("failed to iterate access list items: %w", err)
		}
		itemRows.Close()
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

	_, err = r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	// Update items if provided
	if req.Items != nil {
		// Delete existing items
		_, err = r.db.ExecContext(ctx, `DELETE FROM access_list_items WHERE access_list_id = $1`, id)
		if err != nil {
			return nil, err
		}

		// Insert new items
		for _, item := range req.Items {
			_, err = r.db.ExecContext(ctx, `
				INSERT INTO access_list_items (access_list_id, directive, address, description, sort_order)
				VALUES ($1, $2, $3, $4, $5)
			`, id, item.Directive, item.Address, item.Description, item.SortOrder)
			if err != nil {
				return nil, err
			}
		}
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
