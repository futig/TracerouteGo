package application

import (
	"time"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func listenTCP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult, iface chan gopacket.Packet) {

	timeoutChan := time.After(cfg.Timeout)
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
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SrcPort == layers.TCPPort(cfg.DstPort) && tcp.DstPort == layers.TCPPort(cfg.SrcPort) {
					resultChan <- &domain.PingResult{
						Ip:   srcIP,
						Time: endTime,
					}
					return
				}
			} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if isICMPCorrect(icmp) {
					resultChan <- &domain.PingResult{
						Ip:   srcIP,
						Time: endTime,
					}
					return
				}
			}
		case <-timeoutChan:
			resultChan <- nil
			return
		default:
			continue
		}
	}
}
