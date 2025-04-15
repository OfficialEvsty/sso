package models

import (
	uu "github.com/google/uuid"
	"net"
	"time"
)

// OAuthSession model
type OAuthSession struct {
	Id        uu.UUID   `json:"id" db:"id"`
	ClientId  int       `json:"client_id" db:"client_id"`
	Ip        net.IP    `json:"ip" db:"ipv4"`
	Scope     string    `json:"scope" db:"scope"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

type UserSession struct {
	Id      int64        `json:"id" db:"id"`
	UserId  int64        `json:"user_id" db:"user_id"`
	Session OAuthSession `json:"session" db:"session"`
}

type SessionMetadata struct {
	Id          int     `json:"id" db:"id"`
	RedirectUri string  `json:"redirect_uri" db:"uri"`
	State       string  `json:"state" db:"state"`
	SessionID   uu.UUID `json:"session_id" db:"session_id"`
}
