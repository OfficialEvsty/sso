package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sso/internal/storage/protected"
	"strings"
)

// SignProvider interface allows sign a JWT and give upon request a Public Key
type SignProvider interface {
	SignJWT(ctx context.Context, claims map[string]interface{}, keyVersion int) (string, error)
	RotateKey(ctx context.Context) error
	PublicKey(ctx context.Context, version string) (string, error)
	LatestKeyVersion(ctx context.Context) (int, error)
}

// SignController is a concrete implementation of SignProvider interface
type SignController struct {
	v *protected.Vault
}

// NewSignController creates a new instance of Signer
func NewSignController(client *protected.Vault) *SignController {
	return &SignController{v: client}
}

// LatestKeyVersion gets the latest key version with proper error handling
func (s *SignController) LatestKeyVersion(ctx context.Context) (int, error) {
	secret, err := s.v.Client.Read(ctx, "transit/keys/jwt_keys")
	if err != nil {
		return 0, fmt.Errorf("failed to read key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return 0, fmt.Errorf("empty response from vault")
	}

	versionRaw, ok := secret.Data["latest_version"]
	if !ok {
		return 0, fmt.Errorf("latest_version field missing")
	}

	versionNum, ok := versionRaw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("invalid version format")
	}

	version, err := versionNum.Int64()
	if err != nil {
		return 0, fmt.Errorf("version conversion failed: %w", err)
	}

	return int(version), nil
}

// SignJWT signs a JWT with improved error handling
func (s *SignController) SignJWT(ctx context.Context, claims map[string]interface{}, keyVersion int) (string, error) {
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": fmt.Sprintf("%d", keyVersion),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("header marshaling failed: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("claims marshaling failed: %w", err)
	}

	headerBase64 := base64.RawURLEncoding.WithPadding('=').EncodeToString(headerJSON)
	claimsBase64 := base64.RawURLEncoding.WithPadding('=').EncodeToString(claimsJSON)

	signingData := map[string]interface{}{
		"input":       claimsBase64,
		"key_version": keyVersion,
	}
	secret, err := s.v.Client.Write(ctx, "transit/sign/jwt_keys", signingData)
	if err != nil {
		return "", fmt.Errorf("vault signing failed: %w, %s", err, claimsBase64)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty response from vault")
	}

	signatureRaw, ok := secret.Data["signature"]
	if !ok {
		return "", fmt.Errorf("signature missing in response")
	}

	signature, ok := signatureRaw.(string)
	if !ok {
		return "", fmt.Errorf("invalid signature format")
	}

	// Remove vault prefix if present
	signature = strings.TrimPrefix(signature, "vault:v1:")

	return fmt.Sprintf("%s.%s.%s", headerBase64, claimsBase64, signature), nil
}

// RotateKey rotates the key pair with error handling
func (s *SignController) RotateKey(ctx context.Context) error {
	_, err := s.v.Client.Write(ctx, "transit/keys/jwt_keys/rotate", nil)
	if err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}
	return nil
}

// PublicKey retrieves the public key with version validation
func (s *SignController) PublicKey(ctx context.Context, version string) (string, error) {
	if version == "" {
		return "", fmt.Errorf("version cannot be empty")
	}

	secret, err := s.v.Client.Read(ctx, fmt.Sprintf("transit/keys/jwt_keys/%s", version))
	if err != nil {
		return "", fmt.Errorf("failed to read public key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty response from vault")
	}

	pubKeyRaw, ok := secret.Data["public_key"]
	if !ok {
		return "", fmt.Errorf("public_key missing in response")
	}

	pubKey, ok := pubKeyRaw.(string)
	if !ok {
		return "", fmt.Errorf("invalid public key format")
	}

	return pubKey, nil
}
