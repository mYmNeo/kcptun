package std

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

// UDPEnabled is the toggle for UDP support
var UDPEnabled = false

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// Error represents a SOCKS error
type Error byte

func (err Error) Error() string {
	return "SOCKS error: " + strconv.Itoa(int(err))
}

// SOCKS errors as defined in RFC 1928 section 6.
const (
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
	InfoUDPAssociate        = Error(9)
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

// String serializes SOCKS address a to string form.
func (a Addr) String() string {
	var host, port string

	switch a[0] { // address type
	case AtypDomainName:
		host = string(a[2 : 2+int(a[1])])
		port = strconv.Itoa((int(a[2+int(a[1])]) << 8) | int(a[2+int(a[1])+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

var (
	connectSuccessReply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	emptyBuffer         = make([]byte, MaxAddrLen+3)
)

type bufferItem struct {
	buf []byte
}

var bufferPool = sync.Pool{
	New: func() any {
		return &bufferItem{
			buf: make([]byte, MaxAddrLen+3),
		}
	},
}

func readAddr(r io.Reader, b []byte) (Addr, error) {
	if len(b) < MaxAddrLen {
		return nil, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
	if err != nil {
		return nil, err
	}

	switch b[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, b[2:2+int(b[1])+2])
		return b[:1+1+int(b[1])+2], err
	case AtypIPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case AtypIPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	}

	return nil, ErrAddressNotSupported
}

// SocksHandshake fast-tracks SOCKS initialization to get target address to connect.
func SocksHandshake(rw io.ReadWriter) (net.Conn, error) {
	// Read RFC 1928 for request and reply structure and sizes.
	bufItem := bufferPool.Get().(*bufferItem)
	defer bufferPool.Put(bufItem)

	copy(bufItem.buf, emptyBuffer)
	// read VER, NMETHODS, METHODS
	if _, err := io.ReadFull(rw, bufItem.buf[:2]); err != nil {
		return nil, err
	}
	nmethods := bufItem.buf[1]
	if _, err := io.ReadFull(rw, bufItem.buf[:nmethods]); err != nil {
		return nil, err
	}
	// write VER METHOD
	if _, err := rw.Write([]byte{5, 0}); err != nil {
		return nil, err
	}
	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(rw, bufItem.buf[:3]); err != nil {
		return nil, err
	}
	cmd := bufItem.buf[1]
	addr, err := readAddr(rw, bufItem.buf)
	if err != nil {
		return nil, err
	}
	switch cmd {
	case CmdConnect:
		_, _ = rw.Write(connectSuccessReply)

		rc, err := net.Dial("tcp", addr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to target: %v", err)
		}

		log.Println("Connected", "addr", addr.String())
		return rc, nil
	case CmdUDPAssociate:
		if !UDPEnabled {
			return nil, ErrCommandNotSupported
		}

		conn, ok := rw.(net.Conn)
		if !ok {
			return nil, errors.New("not a net.Conn")
		}
		tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr)
		if !ok {
			return nil, errors.New("local address is not a TCPAddr")
		}

		bufItem := bufferPool.Get().(*bufferItem)
		defer bufferPool.Put(bufItem)

		copy(bufItem.buf, emptyBuffer)
		var listenAddr Addr
		ip := tcpAddr.IP.To4()
		if ip != nil {
			listenAddr = bufItem.buf[:1+net.IPv4len+2]
			listenAddr[0] = AtypIPv4
			copy(listenAddr[1:], ip)
		} else {
			ip = tcpAddr.IP.To16()
			if ip == nil {
				return nil, ErrAddressNotSupported
			}
			listenAddr = bufItem.buf[:1+net.IPv6len+2]
			listenAddr[0] = AtypIPv6
			copy(listenAddr[1:], ip)
		}

		port := tcpAddr.Port
		listenAddr[len(listenAddr)-2] = byte(port >> 8)
		listenAddr[len(listenAddr)-1] = byte(port)

		replyBuf := bufferPool.Get().(*bufferItem)
		defer bufferPool.Put(replyBuf)

		copy(bufItem.buf, emptyBuffer)
		replyBuf.buf[0] = 5
		replyBuf.buf[1] = 0
		replyBuf.buf[2] = 0
		copy(replyBuf.buf[3:], listenAddr)
		_, err = rw.Write(replyBuf.buf[:3+len(listenAddr)])

		if err != nil {
			return nil, ErrCommandNotSupported
		}
		err = InfoUDPAssociate
	default:
		return nil, ErrCommandNotSupported
	}

	return nil, err
}

func SendSocksConnectRequest(rw io.ReadWriter, addr *net.TCPAddr) error {
	bufItem := bufferPool.Get().(*bufferItem)
	defer bufferPool.Put(bufItem)

	copy(bufItem.buf, emptyBuffer)
	// Prepare SOCKS5 CONNECT request
	bufItem.buf[0] = 5 // SOCKS5 version
	bufItem.buf[1] = 1 // NMETHODS command
	bufItem.buf[2] = 0 // NMETHODS value

	_, err := rw.Write(bufItem.buf[:3])
	if err != nil {
		return err
	}

	bufItem.buf[0] = 5          // SOCKS5 version
	bufItem.buf[1] = CmdConnect // CONNECT command
	bufItem.buf[2] = 0          // Reserved byte

	var reqLen int
	// Add address
	ip := addr.IP.To4()
	if ip != nil {
		bufItem.buf[3] = AtypIPv4
		copy(bufItem.buf[4:], ip)
		reqLen = 4 + net.IPv4len
	} else {
		ip = addr.IP.To16()
		if ip == nil {
			return ErrAddressNotSupported
		}
		bufItem.buf[3] = AtypIPv6
		copy(bufItem.buf[4:], ip)
		reqLen = 4 + net.IPv6len
	}

	// Add port
	port := addr.Port
	bufItem.buf[reqLen] = byte(port >> 8)
	bufItem.buf[reqLen+1] = byte(port)
	reqLen += 2

	// Send connect request
	_, err = rw.Write(bufItem.buf[:reqLen])
	if err != nil {
		return err
	}

	return nil
}

func ReadSocksConnectResponse(rw io.ReadWriter) error {
	bufItem := bufferPool.Get().(*bufferItem)
	defer bufferPool.Put(bufItem)

	copy(bufItem.buf, emptyBuffer)
	// Read response
	// 0x5, 0x0, 0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
	n, err := io.ReadFull(rw, bufItem.buf[:len(connectSuccessReply)+2])
	if err != nil {
		return err
	}

	if n != len(connectSuccessReply)+2 {
		return errors.New("invalid socks5 connect response")
	}

	if !bytes.Equal(bufItem.buf[2:n], connectSuccessReply) {
		return errors.New("socks5 connect request failed")
	}

	log.Println("sock5 connected")
	return nil
}
