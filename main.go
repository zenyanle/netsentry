package main

import (
        "fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"netsentry/internal"
)

func main() {
	// 确保输出目录存在
	if err := os.MkdirAll(internal.OutputDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	// 创建通道
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	packetChan := make(chan internal.PacketData, 1000)

	// 启动处理协程
	go internal.ProcessPackets(packetChan)

	// 显示启动信息
	log.Println("NetSentry 启动成功，按 Ctrl+C 停止...")
	fmt.Println("\n=================================================")
	fmt.Println("       NetSentry - 网络流量分析与监控")
	fmt.Println("=================================================")
	fmt.Println("正在监听所有网络接口...")
	fmt.Println("捕获文件保存在: ./pcaps 目录")
	fmt.Println("=================================================\n")

	// 启动捕获
	internal.StartCapture(packetChan, signalChan)

	log.Println("NetSentry 已停止")
}
