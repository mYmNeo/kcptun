package std

import (
	"io"
	"net"
	"strconv"
	"testing"
)

func TestSocksHandshake(t *testing.T) {
	// 创建模拟目标服务器
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("Failed to create target listener:", err)
	}
	defer targetListener.Close()

	// 启动目标服务器接收连接
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err == nil {
				t.Logf("accepted connection: %s", conn.RemoteAddr().String())
				conn.Write([]byte("pong"))
				conn.Close()
			}
		}
	}()

	t.Run("Connect command", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		go func() {
			io.Copy(io.Discard, client)
		}()

		// 获取目标服务器实际地址
		targetAddr := targetListener.Addr().String()
		addr := ParseAddr(targetAddr) // 需要临时恢复ParseAddr或手动构造

		// 构造有效的CONNECT请求
		go func() {
			client.Write([]byte{5, 1, 0}) // METHODS
			// 请求头: VER CMD RSV ATYP DST.ADDR DST.PORT
			request := append([]byte{5, CmdConnect, 0}, addr...)
			client.Write(request)
		}()

		conn, err := SocksHandshake(server)
		if err != nil {
			t.Fatal("Handshake failed:", err)
		}
		defer conn.Close()

		data, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal("Read failed:", err)
		}
		if string(data) != "pong" {
			t.Fatal("Invalid response:", data)
		}
	})

	// 测试UDP Associate命令
	t.Run("UDP Associate command", func(t *testing.T) {
		UDPEnabled = true
		defer func() { UDPEnabled = false }()

		// 创建真实TCP监听器代替net.Pipe
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		ready := make(chan struct{})
		// 客户端连接
		go func() {
			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}

			<-ready
			client.Write([]byte{5, 1, 0})                      // VER, NMETHODS, METHODS
			client.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) // UDP ASSOCIATE
			io.Copy(io.Discard, client)
		}()

		// 服务端连接
		server, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		close(ready)

		_, err = SocksHandshake(server)
		if err != InfoUDPAssociate {
			t.Errorf("Expected UDP associate info, got %v", err)
		}
	})

	// 测试错误命令
	t.Run("Invalid command", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		go func() {
			io.Copy(io.Discard, client)
		}()

		go func() {
			client.Write([]byte{5, 1, 0})                         // METHODS
			client.Write([]byte{5, 0xFF, 0, 1, 0, 0, 0, 0, 0, 0}) // Invalid command
		}()

		_, err := SocksHandshake(server)
		if err != ErrCommandNotSupported {
			t.Errorf("Expected command not supported error, got %v", err)
		}
	})
}

// 临时恢复ParseAddr用于测试
func ParseAddr(s string) Addr {
	host, port, _ := net.SplitHostPort(s)
	ip := net.ParseIP(host)
	var addr []byte
	if ip4 := ip.To4(); ip4 != nil {
		addr = make([]byte, 1+net.IPv4len+2)
		addr[0] = AtypIPv4
		copy(addr[1:], ip4)
	}
	portnum, _ := strconv.Atoi(port)
	addr[len(addr)-2] = byte(portnum >> 8)
	addr[len(addr)-1] = byte(portnum)
	return addr
}
