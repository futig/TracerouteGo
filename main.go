package main

import (
	"fmt"
	"os"
	cli "traceroute/Presentation"
	app "traceroute/Application"
)

func main()  {
	cfg, err := cli.ParseArgs()
	if err != nil {
		ferr := fmt.Errorf("не удалось прочитать аргументы: %w", err)
		fmt.Print(ferr)
		os.Exit(1)
	}
	app.RunTraceroute(cfg)
}