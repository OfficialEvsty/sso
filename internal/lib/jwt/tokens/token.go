package tokens

import (
	"sso/internal/config"
	"sso/internal/domain/models"
	"time"
)

type AccessToken struct {
	Token     string `json:"token"`
	Claims    map[string]interface{}
	ExpiresAt time.Time `json:"expires_at"`
}

// IDToken holds identity data about authenticated user
type IDToken struct {
	Token     string `json:"token"`
	Claims    map[string]interface{}
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenSet holds three tokens: access, id, refresh
type TokenSet struct {
	Access  *AccessToken         `json:"access_token"`
	ID      *IDToken             `json:"id_token"`
	Refresh *models.RefreshToken `json:"refresh_token"`
}

// Type returns type of token
func (t *IDToken) Type() config.TokenType {
	return config.ID
}

// GetClaims returns token's claims
func (t *IDToken) GetClaims() map[string]interface{} {
	return t.Claims
}

// Type returns type of token
func (t *AccessToken) Type() config.TokenType {
	return config.ACCESS
}

// GetClaims returns token's claims
func (t *AccessToken) GetClaims() map[string]interface{} {
	return t.Claims
}

// HasClaim if specified claim contains
func (t *IDToken) HasClaim(claim string) bool {
	_, exists := t.Claims[claim]
	return exists
}

// HasClaim if specified claim contains
func (t *AccessToken) HasClaim(claim string) bool {
	_, exists := t.Claims[claim]
	return exists
}

// ClaimValue returns value of specified key
func (t *AccessToken) ClaimValue(claim string) (interface{}, bool) {
	val, exists := t.Claims[claim]
	return val, exists
}

// ClaimValue returns value of specified key
func (t *IDToken) ClaimValue(claim string) (interface{}, bool) {
	val, exists := t.Claims[claim]
	return val, exists
}
