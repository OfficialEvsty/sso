package models

// User's model
type User struct {
	ID              int64
	Email           string
	PassHash        []byte
	IsEmailVerified bool
}
