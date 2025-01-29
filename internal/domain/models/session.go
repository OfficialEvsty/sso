package models

import "time"

type Session struct {
	UserID    string    `json:"user_id"`
	AppID     string    `json:"app_id"`
	Ip        string    `json:"ip"`
	Device    string    `json:"device"`
	CreatedAt time.Time `json:"created_at"`
}
