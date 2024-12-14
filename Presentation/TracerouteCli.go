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

func ParseCliArguments() (*domain.Configuration, error) {
	if os.Args[1] != "traceroute" {
		return nil, fmt.Errorf("Unknown command")
	}

	args := os.Args[2:]

	config := &domain.Configuration{
		Timeout:     2,
		MaxRequests: 10,
	}

	if len(os.Args) < 2 {
		return nil, fmt.Errorf("Invalid number of arguments. Expected IP address and protocol.")
	}

	// Считываем опции
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			if i+1 < len(args) {
				timeout, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("Invalid timeout value: %v", err)
				}
				config.Timeout = timeout
				i++ // Пропускаем следующий элемент (значение таймаута)
			} else {
				return nil, fmt.Errorf("Missing value for -t")
			}
		case "-p":
			if i+1 < len(args) {
				port, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("Invalid port value: %v", err)
				}
				config.Port = port
				i++ // Пропускаем следующий элемент (значение порта)
			} else {
				return nil, fmt.Errorf("Missing value for -p")
			}
		case "-n":
			if i+1 < len(args) {
				maxRequests, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("Invalid max requests value: %v", err)
				}
				config.MaxRequests = maxRequests
				i++ // Пропускаем следующий элемент (значение max requests)
			} else {
				return nil, fmt.Errorf("Missing value for -n")
			}
		case "-v":
			config.ShowASNumber = true
		default:
			return nil, fmt.Errorf("Unknown flag: %s", args[i])
		}
	}

	// Парсим обязательные параметры: IP-адрес и протокол
	config.IPAddress = args[len(args)-2]
	config.Protocol = strings.ToLower(args[len(args)-1])

	// Проверка на корректность протокола
	if config.Protocol != "tcp" && config.Protocol != "udp" && config.Protocol != "icmp" {
		return nil, fmt.Errorf("Invalid protocol. Expected 'tcp', 'udp' or 'icmp'.")
	}

	// Проверка на наличие порта, если выбран неправильный протокол
	if (config.Protocol == "tcp" || config.Protocol == "udp") && config.Port == 0 {
		return nil, fmt.Errorf("Port must be specified for tcp or udp.")
	}

	return config, nil
}

func readOptions(args []string, cfg *domain.Configuration) (int, error) {
	timeoutSet := false
	portSet := false
	maxRequests := false
	verboseSet := false
	i := 0
	for ; i < len(args); i++ {
		switch args[i] {
		case "-t":
			if timeoutSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			err := parseTimeoutOption(i, args, cfg)
			if err != nil {
				return 0, err
			}
			i++
			timeoutSet = true

		case "-p":
			if portSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			err := parsePortOption(i, args, cfg)
			if err != nil {
				return 0, err
			}
			i++
			portSet = true

		case "-n":
			if maxRequests {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			cfg.Verbose = true
			maxRequests = true

		case "-v":
			if verboseSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			cfg.Guess = true
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

func readIp(ip string, cfg *domain.Configuration) error {
	ipv6 := net.ParseIP(ip)
	if ipv6 == nil {
		fmt.Errorf("invalid IP address '%s'\n", ip)
	}
	cfg.Ip = ipv6.To4()
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

func parseTimeoutOption(i int, args []string, cfg *domain.Configuration) error {
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	cfg.Timeout = time.Second * time.Duration(value)
	return nil
}

func parsePortOption(i int, args []string, cfg *domain.Configuration) error {
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	cfg.Timeout = time.Second * time.Duration(value)
	return nil
}
