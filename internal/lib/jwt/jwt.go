package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"sso/internal/domain/models"
	"time"
)

// GenerateTokenPair generates both tokens access and refresh
func GenerateTokenPair(
	user models.User,
	app models.App,
	accessDuration time.Duration,
) (refresh string, access string, err error) {
	access, err = NewAccessToken(user, app, accessDuration)
	if err != nil {
		return "", "", err
	}

	refresh, err = NewRefreshToken()
	if err != nil {
		return "", "", err
	}
	return refresh, access, nil
}

// NewAccessToken Creates auth-token for specified user and app with limited token's duration
//
// Returns ttl access token in string format
func NewAccessToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
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
