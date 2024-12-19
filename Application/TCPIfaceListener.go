package application

import (
	"fmt"
	"time"
	ut "traceroute/Application/Helpers"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func listenTCP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult, pkt chan gopacket.Packet) {

	timeoutChan := time.After(time.Second * 4)
	for {
		select {
		case packet := <- pkt:
			if packet == nil {
				continue
			}
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			srcIP := networkLayer.NetworkFlow().Src().String()
			fmt.Println(srcIP)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SrcPort == layers.TCPPort(cfg.Port) && tcp.DstPort == layers.TCPPort(domain.SRC_PORT) {
					resultChan <- &domain.PingResult{
						Ip:       srcIP,
						Time:     time.Since(timerStart),
						Finished: true,
					}
					return
				}
			} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if icmp.TypeCode.Type() == 3 {
					if icmp.TypeCode.Code() == 3 {
						resultChan <- &domain.PingResult{
							Ip:       srcIP,
							Time:     time.Since(timerStart),
							Finished: true,
						}
						return
					}
				} else if icmp.TypeCode.Type() == 11 {
					resultChan <- &domain.PingResult{
						Ip:       srcIP,
						Time:     time.Since(timerStart),
						Finished: false,
					}
					return
				}
			}
		case <-timeoutChan:
			fmt.Println("timeout")
			resultChan <- nil
			return
		default:
			continue
		}
	}
}