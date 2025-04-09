package models

// PKCE data model for validating CodeChallenge as a result of CodeVerifier hash made by specified hashing Method
type PKCE struct {
	CodeChallenge string `json:"code_challenge"`
	Method        string `json:"code_challenge_method"`
}
