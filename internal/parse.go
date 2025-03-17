package internal

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketData 结构体用于存储解析后的数据包信息
type PacketData struct {
	Index      int
	Timestamp  time.Time
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
	Protocol   string
	Length     int
	Payload    []byte
}

// 解析捕获的 pcap 文件并将解析结果发送到 chan
func ParsePcapFile(pcapFile string, index int, packetChan chan<- PacketData) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Printf("打开PCAP文件失败 %s: %v\n", pcapFile, err)
		return
	}
	defer handle.Close()

	log.Printf("开始解析文件: %s\n", pcapFile)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 获取时间戳
		timestamp := packet.Metadata().Timestamp

		// 提取IP信息
		var sourceIP, destIP net.IP
		var sourcePort, destPort uint16
		var protocol string
		
		// 获取IP层
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			sourceIP = ip.SrcIP
			destIP = ip.DstIP
			
			// 确定协议
			switch ip.Protocol {
			case layers.IPProtocolTCP:
				protocol = "TCP"
			case layers.IPProtocolUDP:
				protocol = "UDP"
			default:
				protocol = "其他"
			}
		}

		// 获取TCP/UDP层
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			sourcePort = uint16(tcp.SrcPort)
			destPort = uint16(tcp.DstPort)
		} else {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				sourcePort = uint16(udp.SrcPort)
				destPort = uint16(udp.DstPort)
			}
		}

		// 提取 payload
		payload := []byte{}
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload = appLayer.Payload()
		}

		// 发送解析后的数据
		packetChan <- PacketData{
			Index:      index,
			Timestamp:  timestamp,
			SourceIP:   sourceIP,
			DestIP:     destIP,
			SourcePort: sourcePort,
			DestPort:   destPort,
			Protocol:   protocol,
			Length:     len(packet.Data()),
			Payload:    payload,
		}
	}
}
