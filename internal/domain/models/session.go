package models

import "time"

type Session struct {
	UserID    string    `json:"user_id,string"`
	AppID     string    `json:"app_id,string"`
	Ip        string    `json:"ip"`
	Device    string    `json:"device"`
	CreatedAt time.Time `json:"created_at"`
}
