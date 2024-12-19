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
	srcIp := net.ParseIP(domain.SRC_IP).To4()
	dstIp := net.ParseIP(cfg.IPAddress).To4()

	listener, packet, bpfFilter := generatePayloadAndListener(cfg, domain.SRC_IP, domain.SRC_PORT)

	// Создаю сырой сокет с возможностью писать свой ip заголовок
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return err
	}

	// Создаю канал на чтение интерфейса и применяю BPF фильтр на него
	handle, err := pcap.OpenLive(domain.INTERFACE_NAME, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pch := packetSource.Packets()

	writerChan := make(chan *domain.RoutePoint, 100)
	defer close(writerChan)

	// Запускаю логирующую горутину
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for point := range writerChan {
			writer(point, cfg)
		}
	}()

	// Запускаю основной цикл утилиты
	err = TraceLoop(packet.ToBytes(), dstIpAddr, fd, writerChan, listener, cfg)
	if err != nil {
		return err
	}

	wg.Wait()
	return nil
}


func generatePayloadAndListener(cfg *domain.Configuration, srcIp string, srcPort uint16) (
	func(*domain.Configuration, time.Time, chan *domain.PingResult, chan gopacket.Packet), []byte, string) {

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
		filter := fmt.Sprintf("icmp and dst host %s", domain.SRC_IP)

	case 6:
		payloadObj = domain.TCPHeader{
			SourcePort:      srcPort,
			DestinationPort: uint16(cfg.Port),
			SourceIp:        net.IP(srcIp).To4(),
			DestinationIp:   net.IP(cfg.IPAddress).To4(),
		}
		payload = payloadObj.ToBytes()
		listener = listenTCP
		filter := fmt.Sprintf("icmp and dst host %s", domain.SRC_IP)

	case 17:
		payloadObj = domain.UDPHeader{
			SourcePort:      srcPort,
			DestinationPort: uint16(cfg.Port),
			SourceIp:        net.IP(srcIp),
			DestinationIp:   net.IP(cfg.IPAddress),
		}
		payload = payloadObj.ToBytes()
		listener = listenUDPICMP
		filter := fmt.Sprintf("icmp and dst host %s", domain.SRC_IP)

	default:
		return nil, nil, ""
	}

	packet := domain.NewIPv4Header(srcIpAddr, dstIpAddr, 1, cfg.Protocol, payload)
	return listenTCP, packet.ToBytes(), filter
}








func TraceLoop(packet domain.BytesIpv4Header, dstAddr net.IP, sock int, writeChan chan *domain.RoutePoint,
	listener func(*domain.Configuration, time.Time, chan *domain.PingResult, chan gopacket.Packet), cfg *domain.Configuration) error {
	resultChan := make(chan *domain.PingResult, 3)
	defer close(resultChan)

	addr := &syscall.SockaddrInet4{Addr: [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]}}
	ttl := 1



	for true {
		packet.ChangeTTL(byte(ttl))
		for i := 0; i < 3; i++ {
			err := syscall.Sendto(sock, packet, 0, addr)
			if err != nil {
				return err
			}
			timerStart := time.Now()
			go listener(cfg, timerStart, resultChan, pch)
		}
		sendersIps := make(map[string]int, 3)
		var finished bool
		var succesCount int
		var timeSum time.Duration
		for i := 0; i < 3; i++ {
			result := <-resultChan
			if result != nil {
				if ut.CompareIpv4Addresses(net.ParseIP(result.Ip), dstAddr) {
					succesCount = 1
					timeSum = result.Time
					finished = true
					break
				}	packet := domain.NewIPv4Header(srcIpAddr, dstIpAddr, 1, cfg.Protocol, payload)

		}
		break
		if succesCount == 0 {
			writeChan <- &domain.RoutePoint{
				Number: ttl,
				Ip:     "*",
			}
			continue
		}

		var senderIp string
		if finished {
			senderIp = string(dstAddr)
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
