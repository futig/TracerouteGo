package presentation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	domain "traceroute/Domain"
)

func ParseArgs() (*domain.Configuration, error) {
	if os.Args[1] != "traceroute" {
		return nil, fmt.Errorf("unknown command")
	}

	args := os.Args[2:]

	cfg := &domain.Configuration{
		Timeout:     2,
		MaxRequests: 10,
		Port: 33434,
	}

	if len(os.Args) < 2 {
		return nil, fmt.Errorf("invalid number of arguments. Expected IP address and protocol")
	}

	optionsEnd, err := readOptions(args, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if optionsEnd+1 >= len(args) {
		return nil, fmt.Errorf("failed to parse ip: ip not stated")
	}

	err = checkIpAddress(args[optionsEnd+1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip: %w", err)
	}
	cfg.IPAddress = args[optionsEnd+1]

	if optionsEnd+2 >= len(args) {
		return nil, fmt.Errorf("failed to parse protocol: protocol not stated")
	}

	err = ParseProtocol(args[optionsEnd+2], cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse protocol: %w", err)
	}

	return cfg, nil
}

func readOptions(args []string, cfg *domain.Configuration) (int, error) {
	timeoutSet := false
	portSet := false
	requestsLimitSet := false
	verboseSet := false
	i := 0
	for ; i < len(args); i++ {
		switch args[i] {
		case "-t":
			if timeoutSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			err := readTimeoutOption(i, args, cfg)
			if err != nil {
				return 0, err
			}
			i++
			timeoutSet = true

		case "-p":
			if portSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			err := readPortOption(i, args, cfg)
			if err != nil {
				return 0, err
			}
			i++
			portSet = true

		case "-n":
			if requestsLimitSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			err := readRequestsLimitOption(i, args, cfg)
			if err != nil {
				return 0, err
			}
			i++
			requestsLimitSet = true

		case "-v":
			if verboseSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			cfg.ShowASNumber = true
			verboseSet = true

		default:
			if strings.HasPrefix(args[i], "-") {
				return 0, fmt.Errorf("there is no such option: %v", args[i])
			}
			return i - 1, nil
		}
	}

	return i - 1, nil
}

func checkIpAddress(ip string) error {
	ipv6 := net.ParseIP(ip)
	if ipv6 == nil {
		return fmt.Errorf("invalid IP address '%s'", ip)
	}
	return nil
}

func readIntValue(i int, args []string) (int, error) {
	if i+1 >= len(args) {
		return 0, fmt.Errorf("there is no value for option '%v'", args[i])
	}
	value, err := strconv.Atoi(args[i+1])
	if err != nil {
		return 0, fmt.Errorf("value of option '%v' must be integer, not '%T'", args[i], args[i])
	}
	return value, nil
}

func readTimeoutOption(i int, args []string, cfg *domain.Configuration) error {
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	cfg.Timeout = time.Second * time.Duration(value)
	return nil
}

func readPortOption(i int, args []string, cfg *domain.Configuration) error {
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	if value < 0 || 65535 < value {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	cfg.Port = value
	return nil
}

func readRequestsLimitOption(i int, args []string, cfg *domain.Configuration) error {
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	if value < 0 {
		return fmt.Errorf("port must be positiv")
	}
	cfg.MaxRequests = value
	return nil
}

func ParseProtocol(protocol string, cfg *domain.Configuration) error {
	switch protocol {
	case "tcp":
		cfg.Protocol = 6
	case "udp":
		cfg.Protocol = 17
	case "icmp":
		cfg.Protocol = 1
	default:
		return fmt.Errorf("invalid protocol. Expected 'tcp', 'udp' or 'icmp'")
	}
	return nil
}
