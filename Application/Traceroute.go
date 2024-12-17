package application

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	ut "traceroute/Application/Helpers"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func RunTraceroute(cfg *domain.Configuration, writer func(*domain.RoutePoint, *domain.Configuration)) error {
	listener, payload := generatePayloadAndListener(cfg, domain.SRC_IP, domain.SRC_PORT)

	srcIpAddr := net.ParseIP(domain.SRC_IP)
	dstIpAddr := net.ParseIP(cfg.IPAddress)

	ipHeader := domain.NewIPv4Header(srcIpAddr, dstIpAddr, 0, cfg.Protocol, payload)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return err
	}

	writerChan := make(chan *domain.RoutePoint, 100)
	defer close(writerChan)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for point := range writerChan {
			writer(point, cfg)
		}
	}()

	err = TraceLoop(ipHeader.ToBytes(), &dstIpAddr, fd, writerChan, listener, cfg)
	if err != nil {
		return err
	}

	wg.Wait()
	return nil
}

func TraceLoop(packet domain.BytesIpv4Header, dstAddr *net.IP, conn syscall.Handle, writeChan chan *domain.RoutePoint,
	listener func(*domain.Configuration, time.Time, chan *domain.PingResult), cfg *domain.Configuration) error {
	resultChan := make(chan *domain.PingResult, 3)
	defer close(resultChan)

	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], *dstAddr)
	ttl := 1
	for true {
		packet.ChangeTTL(byte(ttl))
		for i := 0; i < 3; i++ {
			err := syscall.Sendto(conn, packet, 0, addr)
			if err != nil {
				return err
			}
			timerStart := time.Now()
			go listener(cfg, timerStart, resultChan)
		}
		sendersIps := make(map[string]int, 3)
		var finished bool
		var succesCount int
		var timeSum time.Duration
		for i := 0; i < 3; i++ {
			result := <-resultChan
			if result != nil {
				if ut.CompareIpv4Addresses(net.ParseIP(result.Ip), *dstAddr) {
					succesCount = 1
					timeSum = result.Time
					finished = true
					break
				}
				succesCount += 1
				timeSum += result.Time
				if _, ok := sendersIps[result.Ip]; !ok {
					sendersIps[result.Ip] = 0
				}
				sendersIps[result.Ip] += 1
			}
		}

		if succesCount == 0 {
			writeChan <- &domain.RoutePoint{
				Number: ttl,
				Ip:     "*",
			}
			continue
		}

		var senderIp string
		if finished {
			senderIp = string(*dstAddr)
		} else {
			senderIp = ut.GetKeyWithMaxValue(sendersIps)
		}

		point := domain.RoutePoint{
			Number: ttl,
			Ip:     senderIp,
			Time:   timeSum / time.Duration(succesCount),
		}
		if cfg.ShowASNumber {
			as, err := QueryWhois(senderIp)
			if err == nil {
				point.AS = as
			}
		}
		writeChan <- &point
		ttl++
		if finished {
			break
		}
	}
	return nil
}

func generatePayloadAndListener(cfg *domain.Configuration, srcIp string, srcPort uint16) (
	func(*domain.Configuration, time.Time, chan *domain.PingResult), []byte) {
	switch cfg.Protocol {
	case 1:
		header := domain.ICMPHeader{
			Type: 8,
		}
		return listenUDPICMP, header.ToBytes()
	case 6:
		header := domain.TCPHeader{
			SourcePort:      srcPort,
			DestinationPort: uint16(cfg.Port),
			SourceIp:        net.IP(srcIp),
			DestinationIp:   net.IP(cfg.IPAddress),
		}
		return listenTCP, header.ToBytes()
	case 17:
		header := domain.UDPHeader{
			SourcePort:      srcPort,
			DestinationPort: uint16(cfg.Port),
			SourceIp:        net.IP(srcIp),
			DestinationIp:   net.IP(cfg.IPAddress),
		}
		return listenUDPICMP, header.ToBytes()
	default:
		return nil, nil
	}
}

func listenTCP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult) {
	handle, err := pcap.OpenLive(domain.INTERFACE_NAME, 65536, true, time.Microsecond)
	if err != nil {
		resultChan <- nil
		return
	}
	defer handle.Close()

	filter := fmt.Sprintf("(tcp and src host %s and src port %d and dst port %d) or (icmp and src host %s)",
		cfg.IPAddress, cfg.Port, domain.SRC_PORT, cfg.IPAddress)
	if err := handle.SetBPFFilter(filter); err != nil {
		resultChan <- nil
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutChan := time.After(cfg.Timeout)

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
			resultChan <- nil
			return
		default:
			continue
		}
	}
}

func listenUDPICMP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult) {
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
				switch icmp.TypeCode.Type() {
				case 3, 0:
					if icmp.TypeCode.Code() == 3 {
						resultChan <- &domain.PingResult{
							Ip:       srcIP,
							Time:     time.Since(timerStart),
							Finished: true,
						}
						return
					}
				case 11:
					resultChan <- &domain.PingResult{
						Ip:       srcIP,
						Time:     time.Since(timerStart),
						Finished: false,
					}
					return
				}
			}
		case <-timeout:
			resultChan <- nil
			return
		default:
			continue
		}
	}
}
