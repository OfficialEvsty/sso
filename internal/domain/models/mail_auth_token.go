package models

import "time"

type MailAuthToken struct {
	Token     string    `json:"token,string"`
	Email     string    `json:"email,string"`
	ExpiresAt time.Time `json:"expiresAt"`
}
