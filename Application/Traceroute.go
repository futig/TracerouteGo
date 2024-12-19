package application

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"syscall"
	"time"
	ut "traceroute/Application/Helpers"
	domain "traceroute/Domain"
	pres "traceroute/Presentation"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func RunTraceroute(cfg *domain.Configuration) error {
	listener, packet, bpfFilter := generateUtilsByProtocol(cfg)

	// Создаю сырой сокет с возможностью писать свой ip заголовок
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)
	err = syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return err
	}

	// Создаю канал на чтение интерфейса и применяю BPF фильтр на него
	handle, err := pcap.OpenLive(cfg.Interface, 65536, true, time.Microsecond)
	if err != nil {
		return nil
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ifacePackets := packetSource.Packets()

	writerChan := make(chan *domain.RoutePoint, 100)
	defer close(writerChan)

	// Запускаю логирующую горутину
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for point := range writerChan {
			if point == nil {
				break
			}
			pres.PrintRoutePoint(point, cfg)
		}
	}()

	// Запускаю основной цикл утилиты
	err = traceLoop(cfg, packet, sock, ifacePackets, writerChan, listener)
	if err != nil {
		return nil
	}

	wg.Wait()
	return nil
}

func generateUtilsByProtocol(cfg *domain.Configuration) (
	func(*domain.Configuration, time.Time, chan *domain.PingResult, chan gopacket.Packet), []byte, string) {

	srcIp := cfg.SrcIp.String()

	var payload []byte
	var listener func(*domain.Configuration, time.Time, chan *domain.PingResult, chan gopacket.Packet)
	var filter string

	switch cfg.Protocol {
	case 1:
		payloadObj := domain.ICMPHeader{
			Type: 8,
		}
		payload = payloadObj.ToBytes()
		listener = listenUDPICMP
		filter = fmt.Sprintf("icmp and (icmp[0] = 0 or icmp[0] = 3 or icmp[0] = 11) and dst host %s", srcIp)

	case 6:
		payloadObj := domain.TCPHeader{
			SourcePort:      cfg.SrcPort,
			DestinationPort: cfg.DstPort,
			SourceIp:        cfg.SrcIp,
			DestinationIp:   cfg.DstIp,
		}
		payload = payloadObj.ToBytes()
		listener = listenTCP
		filter = fmt.Sprintf("host %s and (tcp and dst port %d or (icmp and (icmp[0] = 3 or icmp[0] = 11)))", srcIp, cfg.SrcPort)

	case 17:
		payloadObj := domain.UDPHeader{
			SourcePort:      cfg.SrcPort,
			DestinationPort: cfg.DstPort,
			SourceIp:        cfg.SrcIp,
			DestinationIp:   cfg.DstIp,
		}
		payload = payloadObj.ToBytes()
		listener = listenUDPICMP
		filter = fmt.Sprintf("icmp and (icmp[0] = 0 or icmp[0] = 3 or icmp[0] = 11) and dst host %s", srcIp)

	default:
		return nil, nil, ""
	}

	packet := domain.NewIPv4Header(cfg.SrcIp, cfg.DstIp, 1, cfg.Protocol, payload)
	return listener, packet.ToBytes(), filter
}

func traceLoop(cfg *domain.Configuration, packet domain.BytesIpv4Header, sock int, iface chan gopacket.Packet, writer chan *domain.RoutePoint,
	listener func(*domain.Configuration, time.Time, chan *domain.PingResult, chan gopacket.Packet)) error {

	results := make(chan *domain.PingResult, 3)
	defer close(results)

	// addr := &syscall.SockaddrInet4{Addr: [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]}}
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], cfg.DstIp)

	ttl := 1
	count := 0
	for count < cfg.MaxRequests {
		count++
		packet.ChangeTTL(byte(ttl))
		packet.ChangeIdentifier(uint16(rand.Uint32()))
		for i := 0; i < 3; i++ {
			err := syscall.Sendto(sock, packet, 0, addr)
			if err != nil {
				return err
			}
			timerStart := time.Now()
			go listener(cfg, timerStart, results, iface)
		}

		sendersIps := make(map[string]int, 3)
		var succesCount int
		var finished bool
		var timeSum time.Duration

		for i := 0; i < 3; i++ {
			result := <-results
			if result != nil {
				succesCount += 1
				timeSum += result.Time
				if _, ok := sendersIps[result.Ip]; !ok {
					sendersIps[result.Ip] = 0
				}
				sendersIps[result.Ip] += 1
				if ut.CompareIpv4Addresses(net.ParseIP(result.Ip).To4(), cfg.DstIp) {
					sendersIps[result.Ip] = 999
					finished = true
				}
			}
		}
		if len(sendersIps) == 0 {
			writer <- &domain.RoutePoint{
				Number: ttl,
				Ip:     "*",
			}
			ttl += 1
			continue
		}

		senderIp := ut.GetKeyWithMaxValue(sendersIps)
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

		writer <- &point
		ttl++
		if finished {
			break
		}
	}
	writer <- nil
	return nil
}
