package domain

var ICMPTypes = map[string]int {
	"EchoReply": 0,
	"EchoRequest": 8,
	"TimeExceeded": 11,
}