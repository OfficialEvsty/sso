# Используем многоступенчатую сборку
FROM golang:alpine AS builder

# Устанавливаем рабочую директорию
WORKDIR /sso

# Копируем только необходимые файлы для установки зависимостей
COPY go.mod go.sum ./

# Устанавливаем зависимости
RUN go mod download

# Копируем исходный код
COPY cmd/ ./cmd/
COPY config/ ./config/
COPY internal/ ./internal/

# Собираем приложение
RUN go build -o /sso/main ./cmd/sso/main.go

# Второй этап: создаем минимальный образ
FROM alpine:latest

# Устанавливаем рабочую директорию
WORKDIR /sso

# Копируем только собранный бинарник из первого этапа
COPY --from=builder /sso/main /sso/main

# Копируем конфигурационные файлы
COPY config/local.yaml ./config/local.yaml

# Метаданные
LABEL version="v0.5.2" author="OfficialEvsty" desc="Auth service"

# Указываем точку входа
ENTRYPOINT ["/sso/main"]
CMD ["--config", "./config/local.yaml"]