package domain

import (
	"encoding/binary"
	ut "traceroute/Application/Helpers"
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

	checksum := ut.CalculateChecksum(header)
	binary.BigEndian.PutUint16(header[2:4], checksum)

	return header
}