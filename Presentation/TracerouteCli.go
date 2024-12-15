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
		return nil, fmt.Errorf("Unknown command")
	}

	args := os.Args[2:]

	cfg := &domain.Configuration{
		Timeout:     2,
		MaxRequests: 10,
	}

	if len(os.Args) < 2 {
		return nil, fmt.Errorf("Invalid number of arguments. Expected IP address and protocol.")
	}

	optionsEnd, err := readOptions(args, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if optionsEnd+1 >= len(args) {
		return nil, fmt.Errorf("failed to parse ip: there is no ip")
	}

	err = checkIpAddress(args[optionsEnd+1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip: %w", err)
	}
	cfg.IPAddress = args[optionsEnd+1]

	if optionsEnd+2 >= len(args) {
		return nil, fmt.Errorf("failed to parse ports: there is no ports to scan")
	}

	err = checkProtocol(args[optionsEnd+2], cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ports: %w", err)
	}
	cfg.Protocol = args[optionsEnd+2]

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
		return fmt.Errorf("invalid IP address '%s'\n", ip)
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

func checkProtocol(protocol string, port int) error {
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return fmt.Errorf("Invalid protocol. Expected 'tcp', 'udp' or 'icmp'.")
	}

	if (protocol == "tcp" || protocol == "udp") && port == 0 {
		return fmt.Errorf("Port must be specified for tcp or udp.")
	}

	return nil
}
