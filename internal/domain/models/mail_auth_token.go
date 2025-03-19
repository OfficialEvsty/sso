package models

import "time"

type MailAuthToken struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
}
