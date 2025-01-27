FROM golang:alpine AS builder

WORKDIR /sso

COPY . /sso/

COPY ./migrations /sso/migrations/

# Инициализируем go.mod
RUN go mod init github.com/OfficialEvsty/migrator

RUN go mod tidy
# RUN go get "github.com/golang-migrate/migrate/v4" && go get "github.com/golang-migrate/migrate/v4/database/postgres" && go get "github.com/golang-migrate/migrate/v4/source/file"

# Добавляем необходимые зависимости в go.mod
RUN go get github.com/golang-migrate/migrate/v4
RUN go get github.com/golang-migrate/migrate/v4/database/postgres
RUN go get github.com/golang-migrate/migrate/v4/source/file

RUN go build -o /sso ./main.go

FROM alpine

WORKDIR /sso

COPY --from=builder /sso /sso/

LABEL version="v0.0.1" author="OfficialEvsty" desc="Migrator service"

# ENV

ENTRYPOINT ["/sso/main"]
CMD ["--migrations-path", "migrations"]