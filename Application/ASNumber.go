package application

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

func QueryWhois(ip string) (string, error) {
	server := "whois.apnic.net"

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "%s\r\n", ip)
	if err != nil {
		return "", err
	}

	var responseBuilder strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		responseBuilder.WriteString(scanner.Text() + "\n")
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	ans := responseBuilder.String()
	re := regexp.MustCompile(`(?m)^origin:\s+(AS\d+)`)

	match := re.FindStringSubmatch(ans)
	if len(match) > 1 {
		return match[1], nil
	} 
	return "", nil
}
