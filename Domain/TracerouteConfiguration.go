package domain

import (
	"net"
	"time"
)

type Configuration struct {
	SrcIp        net.IP
	SrcPort      uint16
	DstIp        net.IP
	DstPort      uint16
	Interface    string
	Protocol     byte
	Timeout      time.Duration
	MaxRequests  int
	ShowASNumber bool
}
