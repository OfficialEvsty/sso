package cached

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
)

// UserScopeRepository provides get/set and check allowed scope for specified user
// Cached scope for TokenExchange
type UserScopeRepository struct {
	cache *redis.Client
	db    *postgres.ExtPool
}

// NewUserScopeRepository creates a new instance of UserScopeRepository
func NewUserScopeRepository(db *postgres.ExtPool, cache *redis.Client) *UserScopeRepository {
	return &UserScopeRepository{cache: cache, db: db}
}

// AllowedUserScope returns list of active user's roles
// If user has no one scope returns default 'openid profile'
func (r *UserScopeRepository) AllowedUserScope(
	ctx context.Context,
	userID int64,
	appID int,
) ([]string, error) {
	var roles []string
	sql := "SELECT name FROM roles AS r " +
		"JOIN user_roles AS ur on r.id = ur.role_id " +
		"LEFT JOIN app_roles AS ar ON r.id = ar.role_id " +
		"WHERE ur.user_id = $1 AND (ar.app_id = $2 OR ar.app_id IS NULL) OR r.is_default = TRUE;"

	rows, err := r.db.Query(
		ctx,
		sql,
		userID,
		appID,
	)
	defer rows.Close()
	if err != nil {
		return nil, err
	}
	var roleName string
	for rows.Next() {
		err = rows.Scan(&roleName)
		if err != nil {
			return nil, err
		}
		roles = append(roles, roleName)
	}
	return roles, nil
}

// HasRole Checks whether specified user has a role
// Returns true if user has role, else false
// Throws RoleNotFound if current role doesn't exist
func (r *UserScopeRepository) HasRole(ctx context.Context, userID int64, roleId int32) (bool, error) {
	row := r.db.QueryRow(
		ctx,
		"SELECT id FROM roles WHERE id = $1",
		roleId,
	)
	var checkRoleID int32
	err := row.Scan(&checkRoleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, storage.ErrRoleNotFound
		}
		return false, err
	}

	row = r.db.QueryRow(
		ctx,
		"SELECT id FROM user_roles WHERE user_id = $1 AND role_id = $2",
		userID,
		roleId,
	)
	var userRoleID int64
	err = row.Scan(&userRoleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
