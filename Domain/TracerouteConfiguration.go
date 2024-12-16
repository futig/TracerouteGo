package domain

import "time"

type Configuration struct {
	IPAddress    string
	Protocol     byte
	Timeout      time.Duration
	Port         int
	MaxRequests  int
	ShowASNumber bool
}
