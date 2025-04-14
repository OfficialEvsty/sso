package protected

import (
	"github.com/hashicorp/vault/api"
	"os"
	"sso/internal/lib/extensions"
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
func (v *Vault) AuthUser() (string, error) {
	request := v.Client.NewRequest("POST", "/v1/auth/approle/login")
	login := appRoleLogin{
		SecretID: extensions.GetTextFromFile("./secrets/secret_id.txt"),
		RoleID:   extensions.GetTextFromFile("./secrets/role_id.txt"),
	}

	// Sets login into request's body
	if err := request.SetJSONBody(login); err != nil {
		return "", err
	}

	// step: make the request
	resp, err := v.Client.RawRequest(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// step: parse and return auth
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", err
	}
	return secret.Auth.ClientToken, nil
}
