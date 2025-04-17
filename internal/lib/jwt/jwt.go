package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"sso/internal/config"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt/tokens"
	"sso/internal/storage/protected/vault"
	"time"
)

// TokenProvider creates different token types
type TokenProvider struct {
	sign   *vault.SignController
	claims ClaimsController
	TTLs   map[config.TokenType]time.Duration
}

// NewTokenProvider creates new instance of TokenProvider
func NewTokenProvider(sign *vault.SignController, config config.TokenConfig) *TokenProvider {
	return &TokenProvider{
		sign:   sign,
		claims: NewClaimsController(config.AllowedClaims),
		TTLs:   config.TTLs,
	}
}

// MakeTokenSet collect tokens.IDToken, tokens.AccessToken, models.RefreshToken and make a tokens.TokenSet
func (p *TokenProvider) MakeTokenSet(
	id *tokens.IDToken,
	acs *tokens.AccessToken,
	refresh *models.RefreshToken,
) *tokens.TokenSet {
	return &tokens.TokenSet{
		ID:      id,
		Access:  acs,
		Refresh: refresh,
	}
}

// MakeIDToken turns user claims to base64 encoded string with encrypted sign
func (p *TokenProvider) MakeIDToken(ctx context.Context, user *models.User, aud string) (*tokens.IDToken, error) {
	tokenTTL := p.TTLs[config.ID]
	tokenExpiresAt := time.Now().Add(tokenTTL)
	domain := os.Getenv("WEB_CLIENT_DOMAIN")
	claims := map[string]interface{}{
		"iss":         fmt.Sprintf("https://%s", domain),
		"sub":         user.ID,
		"aud":         aud,
		"iat":         time.Now().Unix(),
		"exp":         tokenExpiresAt.Unix(),
		"email":       user.Email,
		"is_verified": user.IsEmailVerified,
	}
	// Getting latest version of private key to sign a token
	latestKeyVersion, err := p.sign.LatestKeyVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting latest version of JWS key: %w", err)
	}
	// Signs a token with RS256
	signedToken, err := p.sign.SignJWT(ctx, claims, latestKeyVersion)
	if err != nil {
		return nil, err
	}

	idToken := &tokens.IDToken{
		Token:     signedToken,
		Claims:    claims,
		ExpiresAt: tokenExpiresAt,
	}
	// claims validation
	err = p.claims.IsClaimsValid(idToken)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}

// MakeAccessToken Creates auth-token for specified user and app with limited token's duration
func (p *TokenProvider) MakeAccessToken(ctx context.Context, user *models.User, aud string, scope string) (*tokens.AccessToken, error) {
	domain := os.Getenv("WEB_CLIENT_DOMAIN")
	tokenTTL := p.TTLs[config.ACCESS]
	tokenExpiresAt := time.Now().Add(tokenTTL)
	claims := map[string]interface{}{
		"iss":   fmt.Sprintf("https://%s", domain),
		"sub":   user.ID,
		"aud":   aud,
		"scope": scope,
		"exp":   tokenExpiresAt.Unix(),
	}
	latestKeyVersion, err := p.sign.LatestKeyVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting latest version of JWS key: %w", err)
	}

	// Signs a token with RS256
	signedToken, err := p.sign.SignJWT(ctx, claims, latestKeyVersion)

	acsToken := &tokens.AccessToken{
		Token:     signedToken,
		Claims:    claims,
		ExpiresAt: tokenExpiresAt,
	}
	// claims validation
	err = p.claims.IsClaimsValid(acsToken)
	if err != nil {
		return nil, err
	}
	return acsToken, nil
}

// MakeRefreshToken creates refresh token for specified user and app with limited token's duration
//
// Returns ttl refresh token in string format
func (p *TokenProvider) MakeRefreshToken(userID int64) (*models.RefreshToken, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("error while generating refresh token: %w", err)
	}

	// Encrypting token in base64
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	tokenExpiresAt := time.Now().Add(p.TTLs[config.REFRESH])
	return &models.RefreshToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: tokenExpiresAt,
	}, nil
}

// NewVerifyingToken returns verify token
func NewVerifyingToken() (string, error) {
	token := make([]byte, 20)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

//// ValidateAccessToken checks if access token is valid
//func ValidateAccessToken(tokenString string, secret string) (*tokens.AccessToken, error) {
//	token, err := jwt.Parse(tokenString,
//		func(token *jwt.Token) (interface{}, error) {
//			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
//				return nil, fmt.Errorf("There was an error in parsing")
//			}
//			return []byte(secret), nil
//		})
//
//	if err != nil {
//		return nil, err
//	}
//
//	if !token.Valid {
//		return nil, storage.ErrTokenInvalid
//	}
//	if claims, ok := token.Claims.(jwt.MapClaims); ok {
//		expiresAtUnix := int64(claims["exp"].(float64))
//		if expiresAtUnix < (time.Now().Unix()) {
//			return nil, storage.ErrTokenExpired
//		}
//		return &tokens.AccessToken{
//			UserID:    int64(claims["uid"].(float64)),
//			AppID:     int32(claims["app_id"].(float64)),
//			Roles:     strings.Split(claims["roles"].(string), "/"),
//			ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
//		}, nil
//
//	}
//	return nil, jwt.ErrTokenInvalidClaims
//}
