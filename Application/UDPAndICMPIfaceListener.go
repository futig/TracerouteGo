package application

import (
	"time"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func listenUDPICMP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult, iface chan gopacket.Packet) {

	timeout := time.After(cfg.Timeout)
	for {
		select {
		case packet := <-iface:
			if packet == nil {
				continue
			}
			endTime := time.Since(timerStart)
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			srcIP := networkLayer.NetworkFlow().Src().String()
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if isICMPCorrect(icmp) {
					resultChan <- &domain.PingResult{
						Ip:   srcIP,
						Time: endTime,
					}
				}
			}
			return
		case <-timeout:
			resultChan <- nil
			return
		default:
			continue
		}
	}
}

func isICMPCorrect(icmp *layers.ICMPv4) bool {
	typeCode := icmp.TypeCode
	return typeCode.Type() == 3 && typeCode.Code() == 3 || typeCode.Type() == 11 || typeCode.Type() == 0
}
