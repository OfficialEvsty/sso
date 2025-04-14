package vault

import (
	"github.com/hashicorp/vault/api"
	"os"
)

// appRoleLogin holds authenticated data to provide accessed connection to Vault client
type appRoleLogin struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

// Vault is a client instance to Hashicorp Vault secure storage for storing secrets
// Token is a way to access to Vault secret's storage
type Vault struct {
	Token         string
	Client        *api.Client
	LeaseDuration int
}

type Token struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

// NewVaultClient creates new instance of Vault client
func NewVaultClient() (*Vault, error) {
	vaultClient := Vault{}
	client, err := api.NewClient(&api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	vaultClient.Client = client
	return &vaultClient, err
}

// AuthUser authenticated service-user as Vault client
func (v *Vault) AuthUser() error {

}
