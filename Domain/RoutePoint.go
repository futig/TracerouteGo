package domain

import "time"

type RoutePoint struct {
	Number int
	Ip     string
	Time   time.Duration
	AS     string
}
