package models

import (
	"time"
)

// PKCE data model for validating CodeChallenge as a result of CodeVerifier hash made by specified hashing Method
type PKCE struct {
	CodeChallenge string    `json:"code_challenge" db:"code_challenge"`
	Method        string    `json:"code_challenge_method" db:"hash_method"`
	ExpiresAt     time.Time `json:"expires_at" db:"expires_at"`
	SessionID     string    `json:"session_id" db:"session_id"`
}
