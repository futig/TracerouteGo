package domain

import "time"

type Configuration struct {
	IPAddress    string
	Protocol     string
	Timeout      time.Duration
	Port         int
	MaxRequests  int
	ShowASNumber bool
}
