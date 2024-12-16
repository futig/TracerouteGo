package main

import (
	"fmt"
	"os"
	app "traceroute/Application"
	domain "traceroute/Domain"
	cli "traceroute/Presentation"
)

const INTERFACE_NAME = "wlp0s20f3"
const SRC_IP = "192.168.0.108"

func main() {
	cfg, err := cli.ParseArgs()
	if err != nil {
		ferr := fmt.Errorf("не удалось прочитать аргументы: %w", err)
		fmt.Print(ferr)
		os.Exit(1)
	}
	app.RunTraceroute(cfg, INTERFACE_NAME, SRC_IP, PrintOpenPort)
}

func PrintOpenPort(result domain.RoutePoint, cfg *domain.Configuration) {
	// line := fmt.Sprintf("%s %-10s %d %-10s", result.Protocol, " ", result.Port, " ")

	// if cfg.Verbose {
	// 	if result.Protocol == "tcp" {
	// 		line += fmt.Sprintf(" [%dms] %-10s", result.Duration.Milliseconds(), " ")
	// 	} else {
	// 		line += fmt.Sprintf(" [%s] %-10s", "-", " ")
	// 	}
	// }

	// if cfg.Guess {
	// 	guess := result.Guess
	// 	if guess == "" {
	// 		guess = "-"
	// 	}
	// 	line += fmt.Sprintf(" %-6s", guess)
	// }

	// fmt.Println(line)
}
