package helpers

import "net"

func CompareIpv4Addresses(first, second net.IP) bool {
	for i := 0; i < 4; i++ {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}
