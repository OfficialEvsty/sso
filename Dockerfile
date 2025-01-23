FROM golang:alpine AS builder

WORKDIR /sso

COPY cmd/ /sso/cmd/
COPY config/ /sso/config/
COPY internal/ /sso/internal/

ADD go.mod /sso/

RUN export GO111MODULE="on" && go mod tidy

# COPY ["cmd", "config", "internal", "migrations", "./"]

RUN go build -o /sso /sso/cmd/sso/main.go

FROM alpine

WORKDIR /sso

COPY --from=builder /sso /sso/

LABEL version="v0.5.2" author="OfficialEvsty" desc="Auth service"

# ENV

ENTRYPOINT ["/sso/main"]
CMD ["--config", "/sso/config/local.yaml"]