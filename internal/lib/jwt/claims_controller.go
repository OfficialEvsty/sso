package jwt

import (
	"errors"
	"sso/internal/config"
	"sso/internal/services/auth/interfaces"
)

// ClaimsController providing token's claims validation
type ClaimsController interface {
	IsClaimsValid(Token interfaces.ClaimedToken) error
}

// ClaimsControllerImpl concrete implementation of ClaimsController interface
type ClaimsControllerImpl struct {
	ClaimKeysByToken map[config.TokenType][]string
}

// NewClaimsController creates new instance of ClaimsControllerImpl
func NewClaimsController(validClaimKeys map[config.TokenType][]string) *ClaimsControllerImpl {
	return &ClaimsControllerImpl{
		ClaimKeysByToken: validClaimKeys,
	}
}

// IsClaimsValid checks if provided token's claims are valid
func (c *ClaimsControllerImpl) IsClaimsValid(token interfaces.ClaimedToken) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}
	for _, claim := range c.ClaimKeysByToken[token.Type()] {
		if !token.HasClaim(claim) {
			return ErrTokenClaimsIncorrect
		}
		val, _ := token.ClaimValue(claim)
		if val == "" {
			return ErrTokenClaimsIncorrect
		}
	}
	return nil
}
