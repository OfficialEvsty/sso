package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/app/interceptors"
	"sso/internal/domain/models"
	"sso/internal/lib/utilities"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
	"strings"
)

// ValidationRepository validates request's input data
type ValidationRepository struct {
	db *postgres.ExtPool
}

// NewValidationRepository creates new instance of ValidationRepository
func NewValidationRepository(db *postgres.ExtPool) *ValidationRepository {
	return &ValidationRepository{
		db: db,
	}
}

// AuthorizeRequestValidate validates data provided by the client to verify client identity
func (r *ValidationRepository) AuthorizeRequestValidate(ctx context.Context,
	clientID interface{},
	redirectUri string,
	scope string,
	responseType string,
) (validScope string, err error) {
	// checks client
	err = r.validateClientID(ctx, clientID)
	if err != nil {
		return "", err
	}
	// checks redirect uri
	err = r.validateRedirectURI(ctx, redirectUri)
	if err != nil {
		return "", err
	}

	validScope, err = r.validateScope(ctx, scope)
	if err != nil {
		return "", err
	}

	if strings.ToLower(responseType) != "code" {
		return validScope, status.Errorf(codes.InvalidArgument, "unsupported response type: %s", responseType)
	}

	return validScope, nil
}

// TokenArgsValidate validate if client provided valid input data to receive ID and Access Tokens
func (r *ValidationRepository) TokenArgsValidate(ctx context.Context,
	clientID interface{},
	redirectUri string,
	verifier string,
	sessionID string,
) (err error) {
	err = r.validateClientID(ctx, clientID)
	if err != nil {
		return err
	}
	err = r.validateRedirectURI(ctx, redirectUri)
	if err != nil {
		return err
	}
	// PKCE applies only if Production mode assembly
	env := utilities.EnvFromContext(ctx)
	if env != interceptors.EnvProd {
		return nil
	}
	err = r.validatePKCE(ctx, sessionID, verifier)
	return nil
}

// RefreshTokenArgsValidate validate if client provided valid input data to refresh Access Token
func (r *ValidationRepository) RefreshTokenArgsValidate(ctx context.Context,
	clientID interface{},
	clientSecret string,
) (err error) {
	return r.validateClientCredentials(ctx, clientID, clientSecret)
}

// validateScope checks which claims are valid for specified client
func (r *ValidationRepository) validateScope(ctx context.Context, scope string) (string, error) {
	// Split and clean the input scope
	inputScopes := strings.Fields(scope) // Fields handles multiple spaces better than Split
	if len(inputScopes) == 0 {
		return "", nil // or return an error if empty scope is invalid
	}

	// Query database for valid scopes
	rows, err := r.db.Query(
		ctx,
		`SELECT name FROM roles WHERE name = ANY($1)`,
		inputScopes, // pgx automatically converts []string to PostgreSQL array
	)
	if err != nil {
		return "", fmt.Errorf("database query failed: %w", err)
	}
	defer rows.Close()

	// Collect valid scopes
	validScopes := make(map[string]struct{})
	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			return "", fmt.Errorf("scanning role name failed: %w", err)
		}
		validScopes[roleName] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("rows iteration failed: %w", err)
	}

	// Filter original scopes to only include valid ones
	var result []string
	for _, scope := range inputScopes {
		if _, exists := validScopes[scope]; exists {
			result = append(result, scope)
		}
	}

	return strings.Join(result, " "), nil
}

// checks if client_id exists
func (r *ValidationRepository) validateClientID(ctx context.Context, clientID interface{}) error {
	var id interface{}
	err := r.db.QueryRow(
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
func (r *ValidationRepository) validateRedirectURI(ctx context.Context, redirectUri string) error {
	var id interface{}
	err := r.db.QueryRow(
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

// checks if authorization code correct
func (r *ValidationRepository) validateAuthCode(ctx context.Context, authCode string) error {
	var code string
	err := r.db.QueryRow(
		ctx,
		`SELECT code FROM authorization_codes WHERE code = $1`,
		authCode,
	).Scan(&code)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("error while authorization code validation: %w", err)
		}
		return status.Error(codes.InvalidArgument, "invalid authorization code: "+authCode)
	}
	return nil
}

// base64URLEncode encodes byte slice to URL-safe base64 without padding
func base64URLEncode(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(result, "=")
}

// checks if pkce conditions are correct
func (r *ValidationRepository) validatePKCE(ctx context.Context, sessionID string, verifier string) error {
	var pkce models.PKCE
	err := r.db.QueryRow(
		ctx,
		`SELECT * FROM pkces WHERE session_id = $1`,
		sessionID,
	).Scan(&pkce.CodeChallenge, &pkce.Method, &pkce.ExpiresAt, &pkce.SessionID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("error while receiving pkce data: %w", err)
		}
		return status.Error(codes.InvalidArgument, "pkce attended to specified  session ID not found: ")
	}
	// pkce validation (performing hash operation to compare if two hashes are correct)
	var calculatedChallenge string
	switch strings.ToUpper(pkce.Method) {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		calculatedChallenge = base64URLEncode(hash[:])
	case "PLAIN":
		calculatedChallenge = verifier
	default:
		return errors.New("unsupported code challenge method")
	}

	if calculatedChallenge != pkce.CodeChallenge {
		return errors.New("pkce validation failed: code verifier does not match challenge")
	}

	return nil
}

// validateClientCredentials validates provided client's credentials
func (r *ValidationRepository) validateClientCredentials(ctx context.Context, clientID interface{}, clientSecret string) error {
	var id int32
	err := r.db.QueryRow(
		ctx,
		`SELECT * FROM apps WHERE id = $1 AND secret = $2`,
		clientID.(string),
		clientSecret,
	).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrInvalidClientCredentials
		}
		return fmt.Errorf("error while validating client credentials: %w", err)
	}
	return nil
}
