package vault

import (
	"fmt"
	"sso/internal/storage/protected"
)

// SignProvider interface allows sign a JWT and give upon request a Public Key
type SignProvider interface {
	SignJWT(claims map[string]interface{}, keyVersion int) (string, error)
	RotateKey() error
	PublicKey(version string) (string, error)
}

// SignController is a concrete implementation of SignProvider interface
type SignController struct {
	v *protected.Vault
}

// NewSignController creates a new instance of Signer
func NewSignController(client *protected.Vault) *SignController {
	return &SignController{v: client}
}

// SignJWT signs a JWT with private key
func (s *SignController) SignJWT(claims map[string]interface{}, keyVersion int) (string, error) {
	data := map[string]interface{}{"input": claims, "keyVersion": keyVersion}
	secret, err := s.v.Client.Logical().Write("transit/sign/jwt_keys", data)
	if err != nil {
		return "", err
	}
	return secret.Data["signature"].(string), nil
}

// RotateKey rotates pair's key: private and public
func (s *SignController) RotateKey() error {
	_, err := s.v.Client.Logical().Write("transit/keys/jwt_keys/rotate", nil)
	return err
}

// PublicKey give a public key
func (s *SignController) PublicKey(version string) (string, error) {
	secret, err := s.v.Client.Logical().Read(fmt.Sprintf("transit/keys/jwt_keys/%s", version))
	if err != nil {
		return "", err
	}
	return secret.Data["public_key"].(string), nil
}
