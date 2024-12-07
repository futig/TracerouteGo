package domain

import (
	"encoding/binary"
	"fmt"
	infr "traceroute/Infrastructure"
)


type ICMPHeader struct {
	Type byte
	Code byte
}

func NewICMPHeader(messageType, messageCode byte) *ICMPHeader {
	return &ICMPHeader{
		Type: messageType,
		Code: messageCode,
	}
}

func (h *ICMPHeader) ToBytes() []byte {
	header := make([]byte, 8)

	header[0] = h.Type
	header[1] = h.Code

	checksum := infr.CalculateChecksum(header)
	binary.BigEndian.PutUint16(header[2:4], checksum)

	return header
}


func ParseICMPHeader(bytes []byte) (*ICMPHeader, error) {
	if len(bytes) < 8 {
		return nil, fmt.Errorf("invalid ICMP header length")
	}

	icmpType := bytes[0]
	code := bytes[1]

	return &ICMPHeader{
		Type:     icmpType,
		Code:     code,
	}, nil
}