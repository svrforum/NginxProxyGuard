package repository

import (
	"nginx-proxy-guard/internal/database"
)

type WAFRepository struct {
	db *database.DB
}

func NewWAFRepository(db *database.DB) *WAFRepository {
	return &WAFRepository{db: db}
}
