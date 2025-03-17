package internal

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
        "bytes"
)

// 处理从 chan 接收到的数据包
func ProcessPackets(packetChan <-chan PacketData) {
	packetCount := 0
	
	for packetData := range packetChan {
		packetCount++
		processPacket(packetData, packetCount)
	}
}

// 处理单个数据包
func processPacket(packet PacketData, count int) {
	fmt.Printf("\n\n================== 数据包 #%d ==================\n", count)
	fmt.Printf("时间戳: %s\n", packet.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("协议: %s\n", packet.Protocol)
	
	if packet.SourceIP != nil && packet.DestIP != nil {
		if packet.Protocol == "TCP" || packet.Protocol == "UDP" {
			fmt.Printf("连接: %s:%d -> %s:%d\n", 
				packet.SourceIP, packet.SourcePort, 
				packet.DestIP, packet.DestPort)
		} else {
			fmt.Printf("地址: %s -> %s\n", packet.SourceIP, packet.DestIP)
		}
	}
	
	fmt.Printf("长度: %d 字节\n", packet.Length)
	
	// 解码并显示内容
	if len(packet.Payload) > 0 {
		decodedContent := decodeContent(packet.Payload)
		fmt.Printf("内容: %s\n", decodedContent)
	} else {
		fmt.Println("内容: [无数据]")
	}
	
	fmt.Println("===============================================")
}

// 解码数据包内容为人类可读格式
func decodeContent(payload []byte) string {
	if len(payload) == 0 {
		return "[无内容]"
	}

	var result strings.Builder
	
	// 检测并处理常见协议
	if isHTTP(payload) {
		result.WriteString("\n文本内容 (HTTP):\n")
		result.WriteString(formatHTTP(payload))
	} else if isJSON(payload) {
		result.WriteString("\n文本内容 (JSON):\n")
		result.WriteString(string(payload))
	} else if utf8.Valid(payload) {
		// 如果是有效的UTF-8文本
		text := string(payload)
		// 过滤非打印字符
		text = filterNonPrintable(text)
		if text != "" {
			result.WriteString("\n文本内容:\n")
			result.WriteString(text)
		} else {
			result.WriteString("\n[不可打印内容]")
		}
	} else {
		result.WriteString("\n[二进制或加密内容]")
	}

	return result.String()
}

// 检测是否是HTTP请求或响应
func isHTTP(payload []byte) bool {
	httpStart := []string{
		"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ",
		"HTTP/1.", "HTTP/2", 
	}
	
	for _, prefix := range httpStart {
		if bytes.HasPrefix(payload, []byte(prefix)) {
			return true
		}
	}
	
	return false
}

// 格式化HTTP内容
func formatHTTP(payload []byte) string {
	content := string(payload)
	
	// 突出显示请求行/状态行和头部
	lines := strings.Split(content, "\n")
	var formatted strings.Builder
	
	// 突出显示首行
	if len(lines) > 0 {
		formatted.WriteString("▶ " + lines[0] + "\n")
	}
	
	// 处理头部和正文
	inHeaders := true
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		
		// 空行表示头部结束
		if strings.TrimSpace(line) == "" {
			inHeaders = false
			formatted.WriteString("\n")
			continue
		}
		
		if inHeaders {
			// 格式化头部
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				formatted.WriteString("  " + strings.TrimSpace(parts[0]) + ": " + strings.TrimSpace(parts[1]) + "\n")
			} else {
				formatted.WriteString("  " + line + "\n")
			}
		} else {
			// 正文内容
			formatted.WriteString(line + "\n")
		}
	}
	
	return formatted.String()
}

// 检测是否是JSON内容
func isJSON(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	return (bytes.HasPrefix(trimmed, []byte("{")) && bytes.HasSuffix(trimmed, []byte("}")) ||
		bytes.HasPrefix(trimmed, []byte("[")) && bytes.HasSuffix(trimmed, []byte("]")))
}

// 过滤非打印字符
func filterNonPrintable(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
