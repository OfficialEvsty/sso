package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sso/internal/storage/protected"
	"strings"
)

// SignProvider interface allows sign a JWT and give upon request a Public Key
type SignProvider interface {
	SignJWT(claims map[string]interface{}, keyVersion int) (string, error)
	RotateKey() error
	PublicKey(version string) (string, error)
	LatestKeyVersion() (int, error)
}

// SignController is a concrete implementation of SignProvider interface
type SignController struct {
	v *protected.Vault
}

// NewSignController creates a new instance of Signer
func NewSignController(client *protected.Vault) *SignController {
	return &SignController{v: client}
}

// LatestKeyVersion get latest key version
func (s *SignController) LatestKeyVersion() (int, error) {
	secret, err := s.v.Client.Logical().Read("transit/keys/jwt_keys")
	if err != nil {
		return 0, fmt.Errorf("error while read key: %w", err)
	}

	latestVersion := secret.Data["latest_version"].(json.Number)
	version, _ := latestVersion.Int64()
	return int(version), nil
}

// SignJWT signs a JWT with private key
func (s *SignController) SignJWT(claims map[string]interface{}, keyVersion int) (string, error) {
	// Header for JWT, describes what algorithm was used for JWT signification
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": fmt.Sprintf("%d", keyVersion), // Key ID из версии ключа
	}

	// Encoding header and body to base64
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsBase64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	data := map[string]interface{}{"input": claims, "keyVersion": keyVersion}
	secret, err := s.v.Client.Logical().Write("transit/sign/jwt_keys", data)
	if err != nil {
		return "", fmt.Errorf("error while signing token: %w", err)
	}
	signature := strings.TrimPrefix(secret.Data["signature"].(string), "vault:v1:")

	jwt := fmt.Sprintf("%s.%s.%s", headerBase64, claimsBase64, signature)
	return jwt, nil
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
