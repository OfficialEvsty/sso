package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage/postgres"
)

// PKCERepository makes queries to pkce table
type PKCERepository struct {
	db *postgres.ExtPool
}

// NewPKCERepository creates new PKCERepository
func NewPKCERepository(db *postgres.ExtPool) *PKCERepository {
	return &PKCERepository{
		db: db,
	}
}

// PKCE gets pkce data from db
func (r *PKCERepository) PKCE(ctx context.Context, sessionID string) (pkce *models.PKCE, err error) {
	err = r.db.QueryRow(
		ctx,
		`SELECT * FROM pkces WHERE session_id = $1`,
		sessionID,
	).Scan(&pkce)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("error while getting pkce data %w", err)
		}
		return nil, fmt.Errorf("erorr this pkce record not found %w", err)
	}
	return pkce, nil
}

// SavePKCE saves a pair hashed code and hashed method
func (r *PKCERepository) SavePKCE(
	ctx context.Context,
	pkce models.PKCE,
) (err error) {
	_, err = r.db.SaveOrUpdate(
		ctx,
		"pkces",
		pkce,
		"code_challenge")
	if err != nil {
		return fmt.Errorf("save PKCE: %w", err)
	}
	return nil
}

// RemovePKCE removes pkce record from db after usage
func (r *PKCERepository) RemovePKCE(
	ctx context.Context,
	sessionID string,
) (err error) {
	var id interface{}
	err = r.db.QueryRow(
		ctx,
		`DELETE FROM pkces WHERE session_id = $1`,
		sessionID,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("remove PKCE: %w", err)
	}
	return nil
}
