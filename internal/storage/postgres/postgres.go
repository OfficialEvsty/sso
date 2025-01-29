package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"sso/internal/domain/models"
	"sso/internal/lib/extensions"
	"sso/internal/storage"
	"time"
)

// Private config for using inside postgres storage and open connections
type config struct {
	Host     string
	Port     string
	Username string
	Password string
	Database string
	Path     string
}

// Init initialize config instance
func (c *config) Init(storagePath string) {
	/*if storagePath != "" {
		c.Path = storagePath
	}*/
	c.Host = extensions.GetEnv("DB_HOST", "localhost")
	c.Port = extensions.GetEnv("DB_PORT", "5432")
	c.Username = extensions.GetEnv("DB_USER", "postgres")
	c.Password = extensions.GetEnv("DB_PASS", "postgres")
	c.Database = extensions.GetEnv("DB_NAME", "sso_db")
}

// Storage instance for processing sql queries
type Storage struct {
	conf   config
	dbPool *pgxpool.Pool
}

// New initialize an instance of storage db context
func New(storagePath string) (*Storage, error) {
	const op = "storage.postgres.New"

	conf := config{}
	conf.Init(storagePath)
	dbPool, err := pgxpool.New(context.Background(), getConnString(conf))
	if err != nil {
		return nil, errors.New("error connecting to database: " + err.Error())
	}

	return &Storage{conf: conf, dbPool: dbPool}, nil
}

// ends database pool connection
func (s *Storage) CloseStorage() {
	s.dbPool.Close()
}

// getConnString Constructing database connection string
func getConnString(conf config) string {
	var result string
	/*if conf.Path != "" {
		result = fmt.Sprintf("postgres://" + conf.Path + "?sslmode=disable")
		//fmt.Println(result)
		return result
	}*/
	result = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", conf.Username, conf.Password, conf.Host, conf.Port, conf.Database)
	//fmt.Println(result)
	return result
}

// SaveUser saves user in data table 'users'
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	var id int64
	err := s.dbPool.QueryRow(
		ctx,
		"INSERT INTO users(email, hash_pass) values($1, $2) RETURNING id",
		email,
		passHash,
	).Scan(&id)
	if err != nil {
		var pgxError *pgconn.PgError
		if errors.As(err, &pgxError) {
			if pgxError.Code == "23505" {
				return 0, err
			}
		}
		return 0, err
	}
	return id, nil
}

// UserById searches user in database by his ID
func (s *Storage) UserById(ctx context.Context, userID int64) (models.User, error) {
	var user models.User
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT * FROM users WHERE id = $1",
		userID,
	)
	err := row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, err
	}
	return user, nil
}

// User gets user from db by specified his email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	var user models.User
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT * FROM users WHERE email = $1",
		email,
	)
	err := row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, storage.ErrUserNotExist
		}
		return models.User{}, err
	}

	return user, nil
}

// IsAdmin checks whether this user an admin
func (s *Storage) IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error) {
	const op = "storage.postgres.IsAdmin"

	row := s.dbPool.QueryRow(ctx,
		"SELECT * FROM admins WHERE user_id = $1",
		userID)
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Storage) App(ctx context.Context, appID int32) (models.App, error) {
	const op = "storage.postgres.App"
	var app models.App
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT * FROM apps WHERE id = $1",
		appID)
	err := row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}
		return app, err
	}
	return app, err
}

// SaveToken saves refresh token to storage
func (s *Storage) SaveToken(ctx context.Context, tx pgx.Tx, userID int64, token string, expiresAt time.Time) error {
	if tx != nil {
		_, err := tx.Exec(ctx,
			"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID,
			token,
			expiresAt,
		)

		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				return errors.New("error rolling back transaction: " + err.Error())
			}
			return errors.New("error inserting refresh token's data: " + err.Error())
		}

		// Commit all changes
		err = tx.Commit(ctx)
		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				return errors.New("commit error rolling back transaction: " + err.Error())
			}
			return errors.New("error committing refresh token: " + err.Error())
		}
		return nil
	}
	// Delete without transaction logic with rollback
	row := s.dbPool.QueryRow(
		ctx,
		"INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING id",
		userID,
		token,
		expiresAt,
	)

	var refreshTokenId int64
	err := row.Scan(&refreshTokenId)
	if err != nil {
		return errors.New("failed to save refresh token: " + err.Error())
	}
	return nil
}

// Get RefreshToken from db
func (s *Storage) RefreshToken(ctx context.Context, userToken string) (models.RefreshToken, error) {

	var refreshToken models.RefreshToken
	row := s.dbPool.QueryRow(ctx, "SELECT * FROM refresh_tokens WHERE token = $1", userToken)
	err := row.Scan(&refreshToken.ID, &refreshToken.UserID, &refreshToken.Token, &refreshToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RefreshToken{}, storage.ErrTokenInvalid
		}
		return models.RefreshToken{}, err
	}
	return refreshToken, nil
}

// RemoveToken removes refresh token from storage
func (s *Storage) RemoveToken(ctx context.Context, token string, isRollback bool) (*pgx.Tx, error) {
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT id FROM refresh_tokens WHERE token = $1",
		token,
	)
	var oldRefreshTokenId int64
	err := row.Scan(&oldRefreshTokenId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.New("failed to find refresh token to remove: " + err.Error())
	}
	// if needs rollback in next storage calls
	if isRollback {
		tx, err := s.dbPool.Begin(ctx)
		if err != nil {
			return nil, errors.New("failed to start transaction: " + err.Error())
		}
		_, err = tx.Exec(ctx, "DELETE FROM refresh_tokens WHERE id = $1", oldRefreshTokenId)
		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				return nil, errors.New("failed to rollback transaction: " + rollbackErr.Error())
			}
			return nil, errors.New("failed to delete old refresh token: " + err.Error())
		}
		return &tx, nil
	}

	var deleteIndex int64
	row = s.dbPool.QueryRow(ctx,
		"DELETE FROM refresh_tokens WHERE id = $1 RETURNING id", oldRefreshTokenId)
	err = row.Scan(&deleteIndex)
	if err != nil {
		return nil, errors.New("failed to delete refresh token: " + err.Error())
	}
	return nil, nil
}

// Removes all user tokens in db
func (s *Storage) RemoveAllUserTokens(ctx context.Context, userID int64) error {

	_, err := s.dbPool.Exec(
		ctx,
		"DELETE FROM refresh_tokens WHERE user_id = $1",
		userID)

	if err != nil {
		return errors.New("failed to delete refresh tokens of user ID: " + interface{}(userID).(string) + "\n" + err.Error())
	}
	return nil
}

// HasRole Checks whether specified user has a role
// Returns true if user has role, else false
// Throws RoleNotFound if current role doesn't exist
func (s *Storage) HasRole(ctx context.Context, userID int64, roleId int32) (bool, error) {
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT id FROM user_roles WHERE user_id = $1 AND role_id = $2",
		userID,
		roleId,
	)
	var userRoleID int64
	err := row.Scan(&userRoleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// UserRoles returns list of active user's roles
// If user has no one role returns default 'member'
func (s *Storage) UserRoles(
	ctx context.Context,
	userID int64,
	appID int32,
) (*[]string, error) {
	var roles = []string{"member"}
	sql := "WITH RolesJoinUserRoles AS (" +
		"SELECT id, name FROM roles AS r" +
		"INNER JOIN user_roles AS ur ON ur.role_id = r.id" +
		"WHERE ur.user_id = $1)" +
		"SELECT name FROM RolesJoinUserRoles AS rur" +
		"LEFT JOIN app_roles AS ar ON ar.role_id = rur.id" +
		"UNION" +
		"SELECT name FROM RolesJoinUserRoles AS rur" +
		"INNER JOIN app_roles AS ar ON ar.role_id = rur.id" +
		"WHERE app_roles = $2;"

	rows, err := s.dbPool.Query(
		ctx,
		sql,
		userID,
		appID,
	)
	if err != nil {

	}
	return &roles, nil
}
