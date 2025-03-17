package internal

import (
	"fmt"
	"strings"
)

// HexDump 将二进制数据转换为可读的十六进制+ASCII格式
func HexDump(data []byte) string {
	var hexDump strings.Builder
	var asciiDump strings.Builder

	for i, b := range data {
		if i%16 == 0 {
			if i > 0 {
				hexDump.WriteString("  " + asciiDump.String())
				hexDump.WriteString("\n")
				asciiDump.Reset()
			}
			hexDump.WriteString(fmt.Sprintf("%04x: ", i))
		}

		// 写入十六进制值
		hexDump.WriteString(fmt.Sprintf("%02x ", b))

		// 写入ASCII值（只显示可打印字符）
		if b >= 32 && b <= 126 {
			asciiDump.WriteByte(b)
		} else {
			asciiDump.WriteByte('.')
		}

		// 每8个字节添加额外空格
		if i%8 == 7 {
			hexDump.WriteByte(' ')
		}
	}

	// 补全最后一行
	remainder := len(data) % 16
	if remainder > 0 {
		spaces := (16 - remainder) * 3
		if remainder <= 8 {
			spaces += 1 // 额外的中间空格
		}
		hexDump.WriteString(strings.Repeat(" ", spaces))
		hexDump.WriteString("  " + asciiDump.String())
	}

	return hexDump.String()
}

// IsPlaintext 判断数据是否为可读文本
func IsPlaintext(data []byte) bool {
	// 如果超过70%的字节是可打印ASCII字符或常见空白字符，则认为是文本
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printable++
		}
	}
	return len(data) > 0 && float64(printable)/float64(len(data)) > 0.7
}

// ExtractPlaintext 尝试从数据中提取可读文本
func ExtractPlaintext(data []byte) string {
	if !IsPlaintext(data) {
		return "[Binary data]"
	}

	// 替换不可打印字符
	var result strings.Builder
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			result.WriteByte(b)
		} else {
			result.WriteString(".")
		}
	}

	return result.String()
}

// 检测协议类型的简单启发式函数
func DetectProtocol(payload []byte, srcPort, dstPort uint16) string {
	payloadStr := string(payload)

	// 检查常见HTTP模式
	if strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ") ||
		strings.HasPrefix(payloadStr, "HTTP/") {
		return "HTTP"
	}

	// 检查TLS/SSL握手
	if len(payload) > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		return "TLS/SSL"
	}

	// 检查DNS
	if (srcPort == 53 || dstPort == 53) && len(payload) > 12 {
		return "DNS"
	}

	// 检查常见端口
	if srcPort == 80 || dstPort == 80 {
		return "HTTP"
	}
	if srcPort == 443 || dstPort == 443 {
		return "HTTPS"
	}

	return "Unknown"
}
