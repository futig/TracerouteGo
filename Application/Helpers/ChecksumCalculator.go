package helpers

func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}