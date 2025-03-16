package models

import "time"

type MailAuthToken struct {
	Token        string    `json:"token,string"`
	Email        string    `json:"email,string"`
	HashPassword string    `json:"hashPassword,string"`
	ExpiresAt    time.Time `json:"expiresAt"`
}
