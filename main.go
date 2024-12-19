package main

import (
	"fmt"
	"os"
	app "traceroute/Application"
	domain "traceroute/Domain"
	cli "traceroute/Presentation"
)


func main() {
	cfg := &domain.Configuration{}
	err := cli.ReadConfig(cfg)
	CheckException(err, "не удалось прочитать конфигурацию")
	err = cli.ParseArgs(cfg)
	CheckException(err, "не удалось прочитать аргументы")
	err = app.RunTraceroute(cfg)
	CheckException(err, "прозошла ошибка во время выполнения")
}

func CheckException(exc error, message string) {
	if exc != nil {
		ferr := fmt.Errorf("%s: %w",message, exc)
		fmt.Print(ferr)
		os.Exit(1)
	}
}
