package vault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"sso/internal/storage/protected"
	"strings"
)

// JwkProvider interface allows sign a JWT and give upon request a Public Key
type JwkProvider interface {
	SignJWT(ctx context.Context, claims map[string]interface{}, keyVersion int) (string, error)
	RotateKey(ctx context.Context) error
	PublicKeys(ctx context.Context) ([]byte, error)
	LatestKeyVersion(ctx context.Context) (int, error)
}

// JwkManager is a concrete implementation of SignProvider interface
type JwkManager struct {
	v *protected.Vault
}

// NewSignController creates a new instance of Signer
func NewSignController(client *protected.Vault) *JwkManager {
	return &JwkManager{v: client}
}

// LatestKeyVersion gets the latest key version with proper error handling
func (s *JwkManager) LatestKeyVersion(ctx context.Context) (int, error) {
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
func (s *JwkManager) SignJWT(ctx context.Context, claims map[string]interface{}, keyVersion int) (string, error) {
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
func (s *JwkManager) RotateKey(ctx context.Context) error {
	_, err := s.v.Client.Write(ctx, "transit/keys/jwt_keys/rotate", nil)
	if err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}
	return nil
}

// PublicKeys retrieves the public key with version validation
func (s *JwkManager) PublicKeys(ctx context.Context) (jwk.Set, error) {
	secret, err := s.v.Client.Read(ctx, fmt.Sprintf("transit/keys/jwt_keys"))
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty response from vault")
	}

	versions, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("public_key missing in response")
	}
	set := jwk.NewSet()
	for ver, keyData := range versions.(map[string]interface{}) {
		data := keyData.(map[string]interface{})
		pemKey := data["public_key"].(string)
		jwk_, err := convertPemToJwk(pemKey, ver)
		if err != nil {
			return nil, fmt.Errorf("failed to convert public key: %w", err)
		}
		set.Add(jwk_)
	}
	return set, nil
}

func convertPemToJwk(pemKey string, ver string) (jwk.Key, error) {
	// converting to jwk format
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("invalid public key format")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	jwkKey, err := jwk.New(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	_ = jwkKey.Set(jwk.KeyIDKey, ver) // key id
	return jwkKey, nil
}
