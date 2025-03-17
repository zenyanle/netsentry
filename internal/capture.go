package internal

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	OutputDir = "./pcaps"
)

// 启动捕获进程
func StartCapture(packetChan chan<- PacketData, signalChan chan os.Signal) {
	// 获取最新的文件名序号
	index := getLastIndex()

	for {
		// 定义当前文件名
		pcapFile := filepath.Join(OutputDir, fmt.Sprintf("capture_%d.pcapng", index))

		// 启动新的捕获进程
		log.Printf("开始捕获文件 capture_%d.pcapng\n", index)
		currentCmd := exec.Command("sudo", "./ecapture", "tls", "-m", "pcapng", "-i", "any", "--pcapfile", pcapFile)
		if err := currentCmd.Start(); err != nil {
			log.Printf("启动捕获失败: %v\n", err)
			return
		}

		// 等待60秒或者接收到终止信号
		select {
		case <-time.After(60 * time.Second):
			// 终止上一个进程
			if currentCmd.Process != nil {
				if err := currentCmd.Process.Kill(); err != nil {
					log.Printf("终止进程失败: %v\n", err)
				} else {
					log.Printf("捕获文件 %d.pcapng 完成\n", index)
				}
			}

			// 解析捕获的文件
			go ParsePcapFile(pcapFile, index, packetChan)
		case <-signalChan:
			// 处理终止信号
			if currentCmd.Process != nil {
				if err := currentCmd.Process.Kill(); err != nil {
					log.Printf("终止进程失败: %v\n", err)
				} else {
					log.Printf("捕获文件 %d.pcapng 保存成功\n", index)
				}
			}
			// 解析捕获的文件
			go ParsePcapFile(pcapFile, index, packetChan)
			return
		}

		// 更新文件名序号
		index++
		writeLastIndex(index)
		
		// 清理过期的文件 (保留24小时内的文件)
		cleanupExpiredFiles(24 * time.Hour)
	}
}

// 获取最新的文件名序号
func getLastIndex() int {
	// 确保目录存在
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		log.Printf("创建目录失败: %v", err)
	}

	lastIndexFile := filepath.Join(OutputDir, "last_index.txt")
	var index int
	if data, err := os.ReadFile(lastIndexFile); err == nil {
		index, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	} else {
		index = 1
	}
	return index
}

// 写入最新的文件名序号
func writeLastIndex(index int) {
	lastIndexFile := filepath.Join(OutputDir, "last_index.txt")
	if err := os.WriteFile(lastIndexFile, []byte(strconv.Itoa(index)), 0644); err != nil {
		log.Printf("写入索引失败: %v\n", err)
	}
}

// 清理过期的文件
func cleanupExpiredFiles(retentionAge time.Duration) {
	cutoffTime := time.Now().Add(-retentionAge)
	
	files, err := os.ReadDir(OutputDir)
	if err != nil {
		log.Printf("读取目录失败: %v\n", err)
		return
	}
	
	for _, file := range files {
		if file.IsDir() || file.Name() == "last_index.txt" {
			continue
		}
		
		if strings.HasPrefix(file.Name(), "capture_") {
			path := filepath.Join(OutputDir, file.Name())
			info, err := file.Info()
			if err != nil {
				continue
			}
			
			if info.ModTime().Before(cutoffTime) {
				if err := os.Remove(path); err != nil {
					log.Printf("删除文件失败 %s: %v\n", path, err)
				} else {
					log.Printf("已删除过期文件: %s\n", file.Name())
				}
			}
		}
	}
}
