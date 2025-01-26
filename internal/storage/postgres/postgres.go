package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"sso/internal/domain/models"
	"sso/internal/storage"
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

// Simple helper function to read an environment or return a default value
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

// Init initialize config instance
func (c *config) Init(storagePath string) {
	/*if storagePath != "" {
		c.Path = storagePath
	}*/
	c.Host = getEnv("DB_HOST", "localhost")
	c.Port = getEnv("DB_PORT", "5432")
	c.Username = getEnv("DB_USER", "postgres")
	c.Password = getEnv("DB_PASS", "postgres")
	c.Database = getEnv("DB_NAME", "sso_db")
}

// Storage instance for processing sql queries
type Storage struct {
	conf config
}

// New initialize an instance of storage db context
func New(storagePath string) (*Storage, error) {
	const op = "storage.postgres.New"

	conf := config{}
	conf.Init(storagePath)

	return &Storage{conf: conf}, nil
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

	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	if err != nil {
		return 0, err
	}
	var id int64
	err = pool.QueryRow(
		ctx,
		"INSERT INTO users(email, hash_pass) values($1, $2) RETURNING id",
		email,
		passHash,
	).Scan(&id)
	defer pool.Close()
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

// User gets user from db by specified his email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	if err != nil {
		return models.User{}, err
	}
	var user models.User
	row := pool.QueryRow(
		ctx,
		"SELECT * FROM users WHERE email = $1",
		email,
	)
	defer pool.Close()
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
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

	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	if err != nil {
		return false, err
	}

	row := pool.QueryRow(ctx,
		"SELECT * FROM admins WHERE user_id = $1",
		userID)
	defer pool.Close()
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
	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	defer pool.Close()
	if err != nil {
		return models.App{}, err
	}
	row := pool.QueryRow(
		ctx,
		"SELECT * FROM apps WHERE id = $1",
		appID)
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}
		return app, err
	}
	return app, err
}

// SaveRefreshToken saves token to storage
func (s *Storage) SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt int64) (int64, error) {
	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	defer pool.Close()
	if err != nil {
		return 0, errors.New("failed to connect to database")
	}

	row := pool.QueryRow(
		ctx,
		"INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING id",
		userID,
		token,
		expiresAt,
	)

	var refreshTokenId int64
	err = row.Scan(&refreshTokenId)
	if err != nil {
		return 0, errors.New("failed to save refresh token: " + err.Error())
	}
	return refreshTokenId, nil
}

// Get RefreshToken from db
func (s *Storage) RefreshToken(ctx context.Context, token string) (models.RefreshToken, error) {
	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	defer pool.Close()
	if err != nil {
		return models.RefreshToken{}, errors.New("failed to connect to database: " + err.Error())
	}
	var refreshToken models.RefreshToken
	row := pool.QueryRow(ctx, "SELECT * FROM refresh_tokens WHERE token = $1", token)
	err = row.Scan(&refreshToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RefreshToken{}, errors.New("token not found: " + err.Error())
		}
		return models.RefreshToken{}, err
	}
	if refreshToken.ExpiresAt
	return refreshToken, nil
}

// RemoveRefreshToken removes token from storage
func (s *Storage) RemoveRefreshToken(ctx context.Context, token string) (bool, error) {
	pool, err := pgxpool.New(ctx, getConnString(s.conf))
	defer pool.Close()
	if err != nil {
		return false, errors.New("failed to connect to database")
	}

	row := pool.QueryRow(
		ctx,
		"SELECT id FROM refresh_tokens WHERE token = $1",
		token,
	)

	var oldRefreshTokenId int64
	err = row.Scan(&oldRefreshTokenId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, errors.New("failed to find refresh token to remove: " + err.Error())
	}
	var deleteResult bool
	row = pool.QueryRow(ctx,
		"DELETE FROM refresh_tokens WHERE id = $1",
		oldRefreshTokenId)
	err = row.Scan(&deleteResult)
	if err != nil {
		return false, errors.New("failed to delete refresh token: " + err.Error())
	}
	return deleteResult, nil
}
