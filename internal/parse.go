package internal

import (
	"log"
	"net"
	"time"

	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
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

// TCP流重组所需的结构体
type httpStreamFactory struct {
	packetChan chan<- PacketData
	index      int
}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	packetChan     chan<- PacketData
	index          int
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:        net,
		transport:  transport,
		r:          tcpreader.NewReaderStream(),
		packetChan: h.packetChan,
		index:      h.index,
	}
	go hstream.run()
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		data := make([]byte, 4096)
		n, err := buf.Read(data)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream:", err)
			return
		} else if n > 0 {
			// 提取源IP和目的IP
			srcIP := net.IP(h.net.Src().Raw())
			dstIP := net.IP(h.net.Dst().Raw())

			// 提取源端口和目的端口
			srcPortBytes := h.transport.Src().Raw()
			dstPortBytes := h.transport.Dst().Raw()
			srcPort := uint16(srcPortBytes[0])<<8 | uint16(srcPortBytes[1])
			dstPort := uint16(dstPortBytes[0])<<8 | uint16(dstPortBytes[1])

			// 发送流数据
			h.packetChan <- PacketData{
				Index:      h.index,
				Timestamp:  time.Now(), // 注意：流重组无法保留原始时间戳
				SourceIP:   srcIP,
				DestIP:     dstIP,
				SourcePort: srcPort,
				DestPort:   dstPort,
				Protocol:   "TCP",
				Length:     n,
				Payload:    data[:n],
			}
		}
	}
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

	// 设置TCP流组装器
	streamFactory := &httpStreamFactory{packetChan: packetChan, index: index}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// 同时处理单个数据包
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
				// 将TCP数据包送入重组器
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					assembler.AssembleWithTimestamp(
						packet.NetworkLayer().NetworkFlow(),
						tcp,
						packet.Metadata().Timestamp)
				}
			case layers.IPProtocolUDP:
				protocol = "UDP"
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					sourcePort = uint16(udp.SrcPort)
					destPort = uint16(udp.DstPort)

					// 对于UDP，我们直接提取应用层数据
					payload := []byte{}
					appLayer := packet.ApplicationLayer()
					if appLayer != nil {
						payload = appLayer.Payload()

						// 只有当有实际负载时才发送数据
						if len(payload) > 0 {
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
				}
			default:
				protocol = "其他"
				// 对于其他协议类型，直接获取负载（如果有）
				payload := []byte{}
				appLayer := packet.ApplicationLayer()
				if appLayer != nil {
					payload = appLayer.Payload()

					if len(payload) > 0 {
						packetChan <- PacketData{
							Index:      index,
							Timestamp:  timestamp,
							SourceIP:   sourceIP,
							DestIP:     destIP,
							SourcePort: 0,
							DestPort:   0,
							Protocol:   protocol,
							Length:     len(packet.Data()),
							Payload:    payload,
						}
					}
				}
			}
		}
	}

	// 重要：刷新所有挂起的连接
	assembler.FlushAll()
}
