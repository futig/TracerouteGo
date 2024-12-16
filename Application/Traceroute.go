package application

import (
	"fmt"
	"net"
	"syscall"
	"time"
	ut "traceroute/Application/Utils"
	domain "traceroute/Domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func RunTraceroute(cfg *domain.Configuration, srcIp, Interface string, writer func(*domain.RoutePoint, *domain.Configuration)) error {
	payload, listener := generatePayloadAndListener(cfg, srcIp, Interface)

	srcIpAddr := net.ParseIP(srcIp)
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
	go func() {
		for point := range writerChan {
			writer(point, cfg)
		}
		wg
	}()

	err = TraceLoop(ipHeader.ToBytes(), &dstIpAddr, fd, writerChan, listener, cfg)
	if err != nil {
		return err
	}
	return nil
}

func TraceLoop(packet *domain.BytesIpv4Header, dstAddr *net.IP, conn syscall.Handle, writeChan chan *domain.RoutePoint,
	listener func(*domain.Configuration, time.Time, chan *domain.PingResult), cfg *domain.Configuration) error {
	resultChan := make(chan *domain.PingResult, 3)
	defer close(resultChan)

	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], *dstAddr)
	ttl := 1
	for true {
		packet.ChangeTTL(byte(ttl))
		for i := 0; i < 3; i++ {
			err := syscall.Sendto(conn, *packet, 0, addr)
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
			if result.Ip != "*" {
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
			point.AS = "da"
		}
		writeChan <- &point
		ttl++
		if finished {
			break
		}
	}
	return nil
}

func generatePayloadAndListener(cfg *domain.Configuration, srcIp, Interface string) ([]byte,
	func(*domain.Configuration, time.Time, chan *domain.PingResult)) {
	switch cfg.Protocol {
	case 1:
		fmt.Print()
	case 6:
		fmt.Print()
	case 17:
		fmt.Print()
	}
	return nil, nil
}

func listenTCP(cfg *domain.Configuration, timerStart time.Time, resultChan chan *domain.PingResult) {
	handle, err := pcap.OpenLive(INTER, 65536, true, time.Microsecond)
	if err != nil {
		return false, err
	}
	defer handle.Close()
	// Установка BPF-фильтра для захвата релевантных пакетов
	filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d", dstIP.String(), dstPort, srcPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return false, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutChan := time.After(timeout)

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}
				if tcp.SrcPort == layers.TCPPort(dstPort) && tcp.DstPort == layers.TCPPort(srcPort) {
					if tcp.SYN && tcp.ACK {
						return true, nil // Порт открыт
					} else if tcp.RST {
						return false, nil // Порт закрыт
					}
				}
			}
		case <-timeoutChan:
			return false, nil
		default:
			continue
		}
	}
}
