package config

type TokenType int

const (
	ID TokenType = iota
	ACCESS
	REFRESH
)
