package domain

import (
	"encoding/binary"
	"net"
	ut "traceroute/Application/Helpers"
)

type UDPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SourceIp        net.IP
	DestinationIp   net.IP
}

func (h *UDPHeader) ToBytes() []byte {
	header := make([]byte, 8)

	binary.BigEndian.PutUint16(header[0:2], h.SourcePort)
	binary.BigEndian.PutUint16(header[2:4], h.DestinationPort)
	payload := []byte("HEAD / HTTP/1.0\r\n\r\n")
	length := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(header[4:6], length)

	checksum := computeUDPChecksum(h.SourceIp, h.DestinationIp, header, payload)
	binary.BigEndian.PutUint16(header[6:8], checksum)

	return append(header, payload...)
}

func computeUDPChecksum(sourceIP, destinationIP net.IP, udpHeader []byte, payload []byte) uint16 {
	psh := make([]byte, 12)
	copy(psh[0:4], sourceIP.To4())
	copy(psh[4:8], destinationIP.To4())
	psh[8] = 0
	psh[9] = 17

	udpLength := uint16(len(udpHeader) + len(payload))
	psh[10] = byte(udpLength >> 8)
	psh[11] = byte(udpLength & 0xFF)

	data := append(psh, udpHeader...)
	data = append(data, payload...)

	return ut.CalculateChecksum(data)
}
