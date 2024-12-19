package presentation

import (
	"fmt"
	domain "traceroute/Domain"
)

func PrintRoutePoint(result *domain.RoutePoint, cfg *domain.Configuration) {
	line := fmt.Sprintf("%d %-2s %s %-2s", result.Number, " ", result.Ip, " ")

	if result.Ip != "*" {
		line += fmt.Sprintf(" [%dms] %-2s", result.Time.Milliseconds(), " ")
	}

	if result.Ip != "*" && cfg.ShowASNumber {
		line += fmt.Sprintf(" %-2s", result.AS)
	}

	fmt.Println(line)
}
