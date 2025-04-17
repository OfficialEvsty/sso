package protected

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"sso/internal/lib/extensions"
	"time"
)

// Vault is a client instance to Hashicorp Vault secure storage for storing secrets
// Token is a way to access to Vault secret's storage
type Vault struct {
	Token         string
	Client        *vault.Client
	LeaseDuration int
}

type Token struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

// NewVaultClient creates new instance of Vault client in DEV
func NewVaultClient() (*Vault, error) {
	vault_ := Vault{}
	vaultAddr := extensions.GetEnv("VAULT_ADDR", "http://vault:8200")
	client, err := vault.New(
		vault.WithAddress(vaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating new vault client instance: %w", err)
	}
	vault_.Client = client
	err = vault_.Client.SetToken("root")
	if err != nil {
		return nil, fmt.Errorf("error while setting token: %w", err)
	}
	return &vault_, nil
}

// AuthUser authenticated service-user as Vault client
func (v *Vault) AuthUser(ctx context.Context) error {
	resp, err := v.Client.Auth.AppRoleLogin(
		ctx,
		schema.AppRoleLoginRequest{
			RoleId:   extensions.GetTextFromFile("./secrets/role_id.txt"),
			SecretId: extensions.GetTextFromFile("./secrets/secret_id.txt"),
		})

	if err != nil {
		return err
	}
	if err = v.Client.SetToken(resp.Auth.ClientToken); err != nil {
		return err
	}
	return nil
}
