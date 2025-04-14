package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"sso/internal/storage/protected/vault"
	"strings"
	"time"
)

// TokenProvider creates different token types
type TokenProvider struct {
	sign *vault.SignController
	TTLs map[string]time.Duration
}

// NewTokenProvider creates new instance of TokenProvider
func NewTokenProvider(sign *vault.SignController, ttls map[string]time.Duration) *TokenProvider {
	return &TokenProvider{sign: sign, TTLs: ttls}
}

type AccessToken struct {
	UserID    int64     `json:"user_id"`
	AppID     int32     `json:"app_id"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IDToken holds identity data about authenticated user
type IDToken struct {
	Claims    map[string]interface{}
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenSet holds three tokens: access, id, refresh
type TokenSet struct {
	Access  AccessToken         `json:"access_token"`
	ID      IDToken             `json:"id_token"`
	Refresh models.RefreshToken `json:"refresh_token"`
}

// MakeIDToken turns user claims to base64 encoded string with encrypted sign
func (p *TokenProvider) MakeIDToken(user *models.User, aud string) (string, error) {
	claimsSize := 7
	claims := make(map[string]interface{}, claimsSize)
	claims["iss"] = "https://" + os.Getenv("DOMAIN")
	claims["sub"] = user.ID
	claims["aud"] = aud
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(p.TTLs["id"]).Unix()
	claims["email"] = user.Email
	claims["is_verified"] = user.IsEmailVerified
	latestKeyVersion, err := p.sign.LatestKeyVersion()
	if err != nil {
		return "", err
	}
	return p.sign.SignJWT(claims, latestKeyVersion)
}

// GenerateTokenPair generates both tokens access and refresh
func GenerateTokenPair(
	user models.User,
	app models.App,
	roles []string,
	accessDuration time.Duration,
) (refresh string, access string, err error) {
	access, err = NewAccessToken(user, app, roles, accessDuration)
	if err != nil {
		return "", "", err
	}

	refresh, err = NewRefreshToken()
	if err != nil {
		return "", "", err
	}
	return refresh, access, nil
}

// GenerateTokenSet generates three tokens: ID, Access, Refresh
func GenerateTokenSet() {

}

// NewAccessToken Creates auth-token for specified user and app with limited token's duration
//
// Returns ttl access token in string format
func NewAccessToken(user models.User, app models.App, roles []string, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["roles"] = strings.Join(roles, "/")
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// NewRefreshToken creates refresh token for specified user and app with limited token's duration
//
// Returns ttl refresh token in string format
func NewRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	// Encrypting token in base64
	return base64.URLEncoding.EncodeToString(token), nil
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

// ValidateAccessToken checks if access token is valid
func ValidateAccessToken(tokenString string, secret string) (*AccessToken, error) {
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing")
			}
			return []byte(secret), nil
		})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, storage.ErrTokenInvalid
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		expiresAtUnix := int64(claims["exp"].(float64))
		if expiresAtUnix < (time.Now().Unix()) {
			return nil, storage.ErrTokenExpired
		}
		return &AccessToken{
			UserID:    int64(claims["uid"].(float64)),
			AppID:     int32(claims["app_id"].(float64)),
			Roles:     strings.Split(claims["roles"].(string), "/"),
			ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		}, nil

	}
	return nil, jwt.ErrTokenInvalidClaims
}
