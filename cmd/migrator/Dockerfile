FROM golang:alpine AS builder

WORKDIR /sso
RUN ls /sso -R
COPY ../../cmd /sso/cmd/
COPY ../../migrations/ /sso/migrations/

RUN export GO111MODULE="on" && go mod tidy

# COPY ["cmd", "config", "internal", "migrations", "./"]

RUN go build -o /sso /sso/cmd/migrator/main.go

FROM alpine

WORKDIR /sso

COPY --from=builder /sso /sso/

LABEL version="v0.0.1" author="OfficialEvsty" desc="Migrator service"

# ENV

ENTRYPOINT ["/sso/main"]