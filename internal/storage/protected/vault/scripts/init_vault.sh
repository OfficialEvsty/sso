#!/bin/sh

set -e

# Ждём, пока Vault станет доступен
while ! wget -q -O - ${VAULT_ADDR}/v1/sys/health | grep -q '"initialized":true'; do
  echo "Waiting for Vault to start..."
  sleep 1
done

# Включаем AppRole, если ещё не включён
if ! vault auth list | grep -q approle; then
  vault auth enable approle
fi

# Создаём роль (если её нет)
if ! vault read auth/approle/role/my-app-role >/dev/null 2>&1; then
  vault write auth/approle/role/my-app-role \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="default"
fi

# Получаем role_id и secret_id
ROLE_ID=$(vault read -field=role_id auth/approle/role/my-app-role/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/my-app-role/secret-id)

# Сохраняем в файлы (для Docker Secrets)
mkdir -p /secrets
echo "$ROLE_ID" > /secrets/role_id.txt
echo "$SECRET_ID" > /secrets/secret_id.txt

echo "Vault AppRole setup complete!"