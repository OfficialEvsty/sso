package models

type App struct {
	ID          int    `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	RedirectURL string `json:"redirect_url" db:"redirect_url"`
	Secret      string `json:"secret" db:"secret"`
}
