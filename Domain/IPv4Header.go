package domain

import (
	"encoding/binary"
	"fmt"
	"net"

	infr "traceroute/Infrastructure"
)

type IPv4Header struct {
	SourceIP      net.IP
	DestinationIP net.IP
	TimeToLive    byte
	ProtocolType  byte
	Payload       []byte
}

func NewIPv4Header(sourceIP, destinationIP net.IP, timeToLive, protocolType byte, payload []byte) *IPv4Header {
	return &IPv4Header{
		SourceIP: sourceIP,
		DestinationIP: destinationIP,
		TimeToLive: timeToLive,
		ProtocolType: protocolType,
		Payload: payload,
	}
}

func (h *IPv4Header) ToBytes() []byte {
	header := make([]byte, 20)
	// Версия (4 бита) и длина заголовка (4 бита)
	header[0] = 0x45
	// Type of Service
	header[1] = 0
	// Общая длина пакета (заголовок + данные)
	totalLength := uint16(20 + len(h.Payload))
	binary.BigEndian.PutUint16(header[2:4], totalLength)
	// Идентификатор пакета
	binary.BigEndian.PutUint16(header[4:6], 0)
	// Flags и Fragment Offset
	binary.BigEndian.PutUint16(header[6:8], 0)
	// Time to Live
	header[8] = byte(h.TimeToLive)
	// Protocol
	header[9] = byte(h.ProtocolType)
	// Source IP
	copy(header[12:16], h.SourceIP.To4())
	// Destination IP
	copy(header[16:20], h.DestinationIP.To4())
	// Контрольная сумма
	checksum := infr.CalculateChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)

	return append(header, h.Payload...)
}


func ParseIPv4Header(bytes []byte) (*IPv4Header, error) {
	if len(bytes) < 20 {
		return nil, fmt.Errorf("invalid IPv4 header length")
	}
	if bytes[0]>>4 != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}
	headerLength := (bytes[0] & 0x0F) * 4
	if int(headerLength) > len(bytes) {
		return nil, fmt.Errorf("invalid header length")
	}
	timeToLive := bytes[8]
	protocolType := bytes[9]
	sourceIP := net.IP(bytes[12:16])
	destinationIP := net.IP(bytes[16:20])

	payload := bytes[headerLength:]

	return &IPv4Header{
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		TimeToLive:    timeToLive,
		ProtocolType:  protocolType,
		Payload:       payload,
	}, nil
}