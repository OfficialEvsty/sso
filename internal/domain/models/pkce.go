package models

import uu "github.com/google/uuid"

// PKCE data model for validating CodeChallenge as a result of CodeVerifier hash made by specified hashing Method
type PKCE struct {
	CodeChallenge uu.UUID `json:"code_challenge" db:"code_challenge"`
	Method        string  `json:"code_challenge_method" db:"hash_method"`
	SessionID     string  `json:"session_id" db:"session_id"`
}
