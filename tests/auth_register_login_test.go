package tests

import (
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
	"time"
)

const (
	appID     = 2
	appSecret = "test-secret"
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	const passDefaultLength = 16
	email := gofakeit.Email()
	pass := gofakeit.Password(
		true,
		true,
		true,
		true,
		false,
		passDefaultLength,
	)
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	require.NoError(t, err)
	token := respLogin.GetToken()
	assert.NotEmpty(t, token)

	loginTime := time.Now()

	tokenParsed, err := jwt.Parse(
		token,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(appSecret), nil
		})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}
