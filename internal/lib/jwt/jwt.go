package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"strings"
	"time"
)

type TokenProvider struct {
}

type AccessToken struct {
	UserID    int64     `json:"user_id"`
	AppID     int32     `json:"app_id"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IDToken holds identity data about authenticated user
type IDToken struct {
}

// TokenSet holds three tokens: access, id, refresh
type TokenSet struct {
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
