package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage/postgres"
)

// AuthCodeRepository reads/saves auth code between endpoints: Authorize-Token
type AuthCodeRepository struct {
	db *postgres.ExtPool
}

// NewAuthCodeRepository creates new instance of AuthCodeRepository
func NewAuthCodeRepository(db *postgres.ExtPool) *AuthCodeRepository {
	return &AuthCodeRepository{
		db: db,
	}
}

// AuthCode gets models.AuthorizationCode from db
func (r *AuthCodeRepository) AuthCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	var authCode models.AuthorizationCode
	err := r.db.QueryRow(
		ctx,
		`SELECT * FROM authorization_codes WHERE code = $1`,
		code,
	).Scan(&authCode.Code, &authCode.UserID, &authCode.Scope, &authCode.ExpiresAt)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("failed to query authorization code: %w", err)
		}
		return nil, fmt.Errorf("authorization code record not found: %w", err)
	}
	return &authCode, nil
}

// SaveAuthCode saves a models.AuthorizationCode to db
func (r *AuthCodeRepository) SaveAuthCode(ctx context.Context, code *models.AuthorizationCode) (err error) {
	_, err = r.db.SaveOrUpdate(
		ctx,
		"authorization_codes",
		code,
		"code",
	)
	if err != nil {
		return fmt.Errorf("failed to save authorization code: %w", err)
	}
	return nil
}

// RemoveAuthCode deletes models.AuthorizationCode from db by userID
func (r *AuthCodeRepository) RemoveAuthCode(ctx context.Context, userID int64) (err error) {
	_, err = r.db.Exec(
		ctx,
		"DELETE FROM authorization_codes WHERE user_id = $1",
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}
	return nil
}
