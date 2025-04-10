package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"reflect"
	"sso/internal/domain/models"
	"sso/internal/lib/extensions"
	"sso/internal/storage"
	"strings"
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

func (s *Storage) GetConnection() *pgxpool.Pool {
	return s.dbPool
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

// saveOrUpdate сохраняет или обновляет структуру в таблице и возвращает ID
func (s *Storage) saveOrUpdate(ctx context.Context, table string, data interface{}, conflictField string) (interface{}, error) {
	val := reflect.ValueOf(data).Elem()
	typ := val.Type()

	var fields []string
	var placeholders []string
	var values []interface{}
	var updates []string
	counter := 1

	// Определяем имя поля ID (может быть не только "id")
	idField := conflictField
	for i := 0; i < typ.NumField(); i++ {
		if tag := typ.Field(i).Tag.Get("db"); tag == "id" {
			idField = tag
			break
		}
	}

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		dbTag := field.Tag.Get("db")
		if dbTag == "" || dbTag == "-" {
			continue
		}

		fields = append(fields, dbTag)
		placeholders = append(placeholders, fmt.Sprintf("$%d", counter))
		values = append(values, val.Field(i).Interface())

		// Не обновляем поле ID при конфликте
		if dbTag != idField {
			updates = append(updates, fmt.Sprintf("%s = $%d", dbTag, counter))
		}
		counter++
	}

	// Добавляем RETURNING id в запрос
	query := fmt.Sprintf(
		`INSERT INTO %s (%s) VALUES (%s) 
         ON CONFLICT (%s) DO UPDATE SET %s
         RETURNING %s`,
		table,
		strings.Join(fields, ", "),
		strings.Join(placeholders, ", "),
		idField,
		strings.Join(updates, ", "),
		idField,
	)

	var id interface{}
	err := s.dbPool.QueryRow(ctx, query, values...).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to save/update record: %w", err)
	}

	return id, nil
}

func (s *Storage) CheckClientAndRedirectUri(ctx context.Context, clientId int, redirectUri string) error {
	row := s.dbPool.QueryRow(
		ctx,
		`SELECT id FROM apps WHERE client_id = $1 AND redirect_uri = $2`,
		clientId,
		redirectUri,
	)
	var id int
	err := row.Scan(&id)
	if err != nil {
		return errors.New("error checking client id and redirect uri: " + err.Error())
	}
	return nil
}

func (s *Storage) SaveOAuthSession(ctx context.Context, session *models.OAuthSession) (uuid.UUID, error) {
	table := "sessions"
	session.Id = uuid.New()
	sessionID, err := s.saveOrUpdate(ctx, table, session, "id")
	if err != nil {
		return uuid.Nil, err
	}
	uid, err := uuid.Parse(sessionID.(string))
	if err != nil {
		return uuid.Nil, err
	}
	return uid, nil
}

func (s *Storage) SaveSessionMetadata(ctx context.Context, sm *models.SessionMetadata) (int64, error) {
	row := s.dbPool.QueryRow(
		ctx,
		`INSERT INTO redirect_uris(uri, state, session_id) VALUES($1,$2,$3) RETURNING id`,
		sm.RedirectUri,
		sm.State,
		sm.SessionID,
	)
	var id int64
	err := row.Scan(&id)
	if err != nil {
		var pgxError *pgconn.PgError
		if errors.As(err, &pgxError) {
			if pgxError.Code == "23505" {
				return 0, errors.New("session metadata already exists")
			}
		}
		return 0, err
	}
	return id, nil
}

// SaveUser saves user in data table 'users'
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
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
				return 0, storage.ErrUserExists
			}
		}
		return 0, err
	}
	return id, nil
}

// UserById searches user in database by his ID
func (s *Storage) UserById(ctx context.Context, userID int64) (models.User, error) {
	var user models.User
	// get user (probably non verified)
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT * FROM users "+
			"WHERE id = $1",
		userID,
	)
	err := row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, err
	}
	// get verified user
	rows, err := s.dbPool.Query(
		ctx,
		"SELECT * FROM users "+
			"JOIN email_verification ON users.id = user_id "+
			"WHERE users.id = $1",
		userID,
	)
	defer rows.Close()
	user.IsEmailVerified = true
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, err
		}
		user.IsEmailVerified = false
	}
	if !rows.Next() {
		user.IsEmailVerified = false
	}
	return user, nil
}

// User gets user from db by specified his email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	var user models.User
	row := s.dbPool.QueryRow(
		ctx,
		"SELECT * FROM users "+
			"WHERE email = $1",
		email,
	)
	err := row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, storage.ErrUserNotExist
		}
		return models.User{}, err
	}
	userID := user.ID
	// get verified user
	rows, err := s.dbPool.Query(
		ctx,
		"SELECT * FROM users "+
			"JOIN email_verification ON users.id = user_id "+
			"WHERE users.id = $1",
		userID,
	)
	defer rows.Close()
	user.IsEmailVerified = true
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, err
		}
		user.IsEmailVerified = false
	}
	if !rows.Next() {
		user.IsEmailVerified = false
	}

	return user, nil
}

// DeleteUser deletes user with dependencies (refresh token+email verification)
func (s *Storage) DeleteUser(ctx context.Context, userID int64) error {
	result, err := s.dbPool.Query(ctx,
		"DELETE FROM users WHERE id = $1",
		userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("timeout exceeded: " + err.Error())
		}
		return errors.New("error deleting user: " + err.Error())
	}
	defer result.Close()
	return nil
}

// IsAdmin checks whether this user an admin
func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	row := s.dbPool.QueryRow(ctx,
		"SELECT id FROM admins WHERE user_id = $1",
		userID)
	var id int64
	err := row.Scan(&id)
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
func (s *Storage) SaveToken(ctx context.Context, tx pgx.Tx, userID int64, token string, expiresAt time.Time) (int64, error) {
	var tokenID int64
	if tx != nil {
		row := tx.QueryRow(ctx,
			"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING id",
			userID,
			token,
			expiresAt,
		)

		err := row.Scan(&tokenID)

		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				return 0, errors.New("error rolling back transaction: " + err.Error())
			}
			return 0, errors.New("error inserting refresh token's data: " + err.Error())
		}

		// Commit all changes
		err = tx.Commit(ctx)
		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				return 0, errors.New("commit error rolling back transaction: " + err.Error())
			}
			return 0, errors.New("error committing refresh token: " + err.Error())
		}
		return tokenID, nil
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
		return 0, errors.New("failed to save refresh token: " + err.Error())
	}
	return refreshTokenId, nil
}

// Get RefreshToken from db
func (s *Storage) RefreshToken(ctx context.Context, userToken string) (*models.RefreshToken, error) {

	var refreshToken models.RefreshToken
	row := s.dbPool.QueryRow(ctx, "SELECT * FROM refresh_tokens WHERE token = $1", userToken)
	err := row.Scan(&refreshToken.ID, &refreshToken.UserID, &refreshToken.Token, &refreshToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &models.RefreshToken{}, storage.ErrTokenInvalid
		}
		return &models.RefreshToken{}, err
	}
	return &refreshToken, nil
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

	row = s.dbPool.QueryRow(
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

// UserRoles returns list of active user's roles
// If user has no one role returns default 'member'
func (s *Storage) UserRoles(
	ctx context.Context,
	userID int64,
) (*[]string, error) {
	var roles = []string{"member"}
	// Finds intersection of left join and inner join with condition
	/*sql := "WITH RolesJoinUserRoles AS (" +
	"SELECT r.id, r.name FROM roles AS r " +
	"INNER JOIN user_roles AS ur ON ur.role_id = r.id " +
	"WHERE ur.user_id = $1) " +
	"SELECT name FROM RolesJoinUserRoles AS rur " +
	"LEFT JOIN app_roles AS ar ON ar.role_id = rur.id " +
	"UNION " +
	"SELECT name FROM RolesJoinUserRoles AS rur " +
	"INNER JOIN app_roles AS ar ON ar.role_id = rur.id " +
	"WHERE ar.app_id = $2;"*/
	sql := "SELECT name FROM roles AS r " +
		"JOIN user_roles AS ur on r.id = ur.role_id " +
		"LEFT JOIN app_roles AS ar ON r.id = ar.role_id " +
		"WHERE ur.user_id = $1 AND (ar.app_id IS NULL);"

	rows, err := s.dbPool.Query(
		ctx,
		sql,
		userID,
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
	return &roles, nil
}

// AssignRole adds role to specified user
func (s *Storage) AssignRole(ctx context.Context, userID int64, roleID int32) (bool, error) {
	row := s.dbPool.QueryRow(
		ctx,
		"INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) RETURNING id",
		userID,
		roleID,
	)
	var userRoleID int64
	err := row.Scan(&userRoleID)
	if err != nil {
		return false, err
	}
	return true, nil
}

// RevokeRole revokes role from specified user
func (s *Storage) RevokeRole(ctx context.Context, userID int64, roleId int32) (bool, error) {
	row := s.dbPool.QueryRow(
		ctx,
		"DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 RETURNING id",
		userID,
		roleId,
	)
	var userRoleID int64
	err := row.Scan(&userRoleID)
	if err != nil {
		return false, err
	}
	return true, nil
}

// SaveVerifiedUserEmail confirms user's verification in storage
func (s *Storage) SaveVerifiedUserEmail(ctx context.Context, userID int64, email string) error {
	row := s.dbPool.QueryRow(
		ctx,
		"INSERT INTO email_verification (user_id, email) VALUES ($1, $2) RETURNING id",
		userID,
		email,
	)
	var userVerifiedID int64
	err := row.Scan(&userVerifiedID)
	if err != nil {
		return err
	}
	return nil
}

// Validator implementation logic

// AuthorizeRequestValidate validates data provided by the client to verify client identity
func (s *Storage) AuthorizeRequestValidate(ctx context.Context,
	clientID interface{},
	redirectUri string,
	scope string,
	responseType string,
) (validScope string, err error) {
	// checks client
	err = s.validateClientID(ctx, clientID)
	if err != nil {
		return "", err
	}
	// checks redirect uri
	err = s.validateRedirectURI(ctx, redirectUri)
	if err != nil {
		return "", err
	}

	validScope, err = s.validateScope(ctx, scope)
	if err != nil {
		return "", err
	}

	if strings.ToLower(responseType) != "code" {
		return validScope, status.Errorf(codes.InvalidArgument, "unsupported response type: %s", responseType)
	}

	return validScope, nil
}

// validateScope checks which claims are valid for specified client
func (s *Storage) validateScope(ctx context.Context, scope string) (validatedScope string, err error) {
	result := strings.Fields(scope) // Fields handles multiple spaces better than Split
	if len(result) == 0 {
		return "", nil
	}
	textArray := &pgtype.Array[string]{
		Elements: result,
		Valid:    true,
	}

	rows, err := s.dbPool.Query(
		ctx,
		`SELECT id FROM roles WHERE name = ANY($1)`,
		textArray,
	)
	defer rows.Close()
	var validScopes []string
	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			return "", fmt.Errorf("scanning role name failed: %w", err)
		}
		validScopes = append(validScopes, roleName)
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("rows iteration failed: %w", err)
	}
	return strings.Join(validScopes, " "), nil
}

// checks if client_id exists
func (s *Storage) validateClientID(ctx context.Context, clientID interface{}) error {
	var id interface{}
	err := s.dbPool.QueryRow(
		ctx,
		`SELECT id FROM apps WHERE id = $1`,
		clientID,
	).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return status.Error(codes.InvalidArgument, "invalid client id: "+clientID.(string))
	}
	return nil
}

// checks if redirect uri correct
func (s *Storage) validateRedirectURI(ctx context.Context, redirectUri string) error {
	var id interface{}
	err := s.dbPool.QueryRow(
		ctx,
		`SELECT id FROM apps WHERE redirect_uri = $1`,
		redirectUri,
	).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return status.Error(codes.InvalidArgument, "invalid redirect uri: "+redirectUri)
	}
	return nil
}

// ActiveSession gets active user's session
func (s *Storage) ActiveSession(ctx context.Context, sessionID string) (*models.UserSession, error) {
	var userSession models.UserSession
	row := s.dbPool.QueryRow(
		ctx,
		`SELECT us.id, us.user_id, s.id, s.client_id, s.ipv4, s.scope, s.created_at, s.expires_at FROM user_sessions AS us 
		JOIN sessions AS s ON us.session_id = s.id 
		WHERE us.session_id = $1`,
		sessionID,
	)
	err := row.Scan(
		&userSession.Id,
		&userSession.UserId,
		&userSession.Session.Id,
		&userSession.Session.ClientId,
		&userSession.Session.Ip,
		&userSession.Session.Scope,
		&userSession.Session.CreatedAt,
		&userSession.Session.ExpiresAt,
	)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, pgx.ErrNoRows
	}
	return &userSession, nil
}
