package domain

import "time"

type PingResult struct {
	Ip   string
	Time time.Duration
	Finished   bool
}
