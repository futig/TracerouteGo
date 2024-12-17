package main

import (
	"fmt"
	"os"
	app "traceroute/Application"
	domain "traceroute/Domain"
	cli "traceroute/Presentation"
)



func main() {
	cfg, err := cli.ParseArgs()
	if err != nil {
		ferr := fmt.Errorf("не удалось прочитать аргументы: %w", err)
		fmt.Print(ferr)
		os.Exit(1)
	}
	app.RunTraceroute(cfg, PrintOpenPort)
}

func PrintOpenPort(result *domain.RoutePoint, cfg *domain.Configuration) {
	line := fmt.Sprintf("%d %-10s %s %-10s", result.Number, " ", result.Ip, " ")

	if result.Ip != "*" {
		line += fmt.Sprintf(" [%dms] %-10s", result.Time.Milliseconds(), " ")
	}

	if result.Ip != "*" && cfg.ShowASNumber {
		line += fmt.Sprintf(" %-6s", result.AS)
	}

	fmt.Println(line)
}
