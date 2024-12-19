package presentation

import (
    "fmt"
    "net"
    "strconv"
	domain "traceroute/Domain"

    "gopkg.in/ini.v1"
)


func ReadConfig(config *domain.Configuration) error {
    cfg, err := ini.Load("config.ini")
    if err != nil {
        return err
    }

    networkSection := cfg.Section("source")

    srcIPStr := networkSection.Key("source-ip").String()
    srcPortStr := networkSection.Key("source-port").String()
   	ifaceName := networkSection.Key("interface-name").String()

    srcIP := net.ParseIP(srcIPStr)
    if srcIP == nil {
        return fmt.Errorf("неверный IP адрес: %s", srcIPStr)
    }

    srcPort64, err := strconv.Atoi(srcPortStr)
    if err != nil {
        return err
    }

	config.SrcIp = srcIP.To4()
	config.SrcPort = uint16(srcPort64)
	config.Interface = ifaceName
    return nil
}
