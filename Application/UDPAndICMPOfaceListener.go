package application

import (
	"fmt"
	"time"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func listenUDPICMP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult, pkt chan gopacket.Packet) {
	handle, err := pcap.OpenLive(domain.INTERFACE_NAME, 65536, true, time.Microsecond)
	if err != nil {
		resultChan <- nil
		return
	}
	defer handle.Close()

	filter := fmt.Sprintf("icmp and src host %s", cfg.IPAddress)
	if err := handle.SetBPFFilter(filter); err != nil {
		resultChan <- nil
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(cfg.Timeout)

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			srcIP := networkLayer.NetworkFlow().Src().String()
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				pingRes := &domain.PingResult{
					Ip:       srcIP,
					Time:     time.Since(timerStart),
					Finished: true,
				}
				switch icmp.TypeCode.Type() {
				case 3, 0:
					pingRes.Finished = true
				case 11:
					pingRes.Finished = false
				}
				resultChan <- pingRes
			}
		case <-timeout:
			resultChan <- nil
			return
		default:
			continue
		}
	}
}
