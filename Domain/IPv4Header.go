package domain

import (
	"encoding/binary"
	"fmt"
	"net"

	ut "traceroute/Application/Helpers"
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

func (h *IPv4Header) ToBytes() BytesIpv4Header {
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
	checksum := ut.CalculateChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)

	return append(header, h.Payload...)
}

type BytesIpv4Header []byte;

func (h BytesIpv4Header) ChangeTTL(ttl byte) (error) {
	if len(h) < 20 {
		return fmt.Errorf("invalid IPv4 header length")
	}
	h[8] = ttl
	return nil
}

func (h BytesIpv4Header) ChangeIdentifier(id uint16) (error) {
	binary.BigEndian.PutUint16(h[4:6], id)

	return nil
}