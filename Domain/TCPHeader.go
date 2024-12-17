package domain

import (
	"encoding/binary"
	"net"
	ut "traceroute/Application/Helpers"
)

type TCPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SourceIp        net.IP
	DestinationIp   net.IP
}

func (h *TCPHeader) ToBytes() []byte {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], h.SourcePort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], h.DestinationPort)
	tcpHeader[12] = byte(5) << 4
	tcpHeader[13] = byte(2)
	binary.BigEndian.PutUint16(tcpHeader[14:16], uint16(14600))

	checksum := computeTCPChecksum(h.SourceIp, h.DestinationIp, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	return tcpHeader
}

func computeTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(20))
	checksumData := append(pseudoHeader, tcpHeader...)

	return ut.CalculateChecksum(checksumData)
}