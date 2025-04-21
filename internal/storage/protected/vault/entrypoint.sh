#!/bin/sh

# Запускаем Vault в фоновом режиме с логированием
vault server -dev \
  -dev-root-token-id=root \
  -dev-listen-address=0.0.0.0:${VAULT_PORT} \
  > /var/log/vault.log 2>&1 &

# Ждем инициализации Vault
while ! wget -q -O - ${VAULT_ADDR}/v1/sys/health | grep -q '"initialized":true'; do
  echo "Waiting for Vault to start..."
  sleep 1
done

# Выполняем настройку AppRole
export VAULT_TOKEN='root'
export VAULT_ADDR="http://0.0.0.0:${VAULT_PORT}"

if ! vault auth list | grep -q approle; then
  vault auth enable approle
fi

if ! vault read auth/approle/role/my-app-role >/dev/null 2>&1; then
  vault write auth/approle/role/my-app-role \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="default"
fi

# Сохраняем credentials
mkdir -p /secrets
vault read -field=role_id auth/approle/role/my-app-role/role-id > /secrets/role_id.txt
vault write -f -field=secret_id auth/approle/role/my-app-role/secret-id > /secrets/secret_id.txt

echo "Vault AppRole setup complete!"

vault secrets enable transit
vault write transit/keys/jwt_keys \
    type=rsa-2048 \
    allowed_uses=sign,verify \
    exportable=true \
    allow_plaintext_backup=true

echo "Secrets enabled and JWT keys created"
# Оставляем контейнер работающим
tail -f /var/log/vault.log