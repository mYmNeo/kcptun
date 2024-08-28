// The MIT License (MIT)
//
// # Copyright (c) 2016 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/kcptun/config/client"
	"github.com/xtaci/kcptun/std"
	"github.com/xtaci/qpp"
	"github.com/xtaci/smux"
)

const (
	// maximum supported smux version
	maxSmuxVer = 2
	// scavenger check period
	scavengePeriod = 5
)

var (
	SALT = "kcp-go"
)

// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

func main() {
	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "client(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "vps:29900",
			Usage: `kcp server address, eg: "IP:29900" a for single port, "IP:minport-maxport" for port range`,
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none, null",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.BoolFlag{
			Name:  "QPP",
			Usage: "enable Quantum Permutation Pads(QPP)",
		},
		cli.IntFlag{
			Name:  "QPPCount",
			Value: 61,
			Usage: "the prime number of pads to use for QPP: The more pads you use, the more secure the encryption. Each pad requires 256 bytes.",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "set num of UDP connections to server",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 0,
			Usage: "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
		},
		cli.IntFlag{
			Name:  "scavengettl",
			Value: 600,
			Usage: "set how long an expired connection can live (in seconds)",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "ratelimit",
			Value: 0,
			Usage: "set maximum outgoing speed (in bytes per second) for a single KCP connection, 0 to disable. Enabling this will improve the stability of connections under high speed.",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 128,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 512,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  50,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:  "sockbuf",
			Value: 4194304, // socket buffer size in bytes
			Usage: "per-socket buffer in bytes",
		},
		cli.IntFlag{
			Name:  "smuxver",
			Value: 2,
			Usage: "specify smux version, available 1,2",
		},
		cli.IntFlag{
			Name:  "smuxbuf",
			Value: 4194304,
			Usage: "the overall de-mux buffer in bytes",
		},
		cli.IntFlag{
			Name:  "framesize",
			Value: 8192,
			Usage: "smux max frame size",
		},
		cli.IntFlag{
			Name:  "streambuf",
			Value: 2097152,
			Usage: "per stream receive buffer in bytes, smux v2+",
		},
		cli.IntFlag{
			Name:  "keepalive",
			Value: 10, // nat keepalive interval in seconds
			Usage: "seconds between heartbeats",
		},
		cli.IntFlag{
			Name:  "closewait",
			Value: 0,
			Usage: "the seconds to wait before tearing down a connection",
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "to suppress the 'stream open/close' messages",
		},
		cli.BoolFlag{
			Name:  "tcp",
			Usage: "to emulate a TCP connection(linux)",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
		cli.BoolFlag{
			Name:  "pprof",
			Usage: "start profiling server on :6060",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := client.Config{}
		config.LocalAddr = c.String("localaddr")
		config.RemoteAddrs = c.StringSlice("remoteaddrs")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.Conn = c.Int("conn")
		config.AutoExpire = c.Int("autoexpire")
		config.ScavengeTTL = c.Int("scavengettl")
		config.MTU = c.Int("mtu")
		config.RateLimit = c.Int("ratelimit")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.NoComp = c.Bool("nocomp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.SmuxBuf = c.Int("smuxbuf")
		config.FrameSize = c.Int("framesize")
		config.StreamBuf = c.Int("streambuf")
		config.SmuxVer = c.Int("smuxver")
		config.KeepAlive = c.Int("keepalive")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.TCP = c.Bool("tcp")
		config.Pprof = c.Bool("pprof")
		config.QPP = c.Bool("QPP")
		config.QPPCount = c.Int("QPPCount")
		config.CloseWait = c.Int("closewait")

		if c.String("c") != "" {
			err := client.ParseJSONConfig(&config, c.String("c"))
			checkError(err, "parseJSONConfig", "error", err)
		}

		var level slog.Level
		switch strings.ToUpper(config.LogLevel) {
		case "DEBUG":
			level = slog.LevelDebug
		case "INFO":
			level = slog.LevelInfo
		case "WARN":
			level = slog.LevelWarn
		case "ERROR":
			level = slog.LevelError
		default:
			level = slog.LevelInfo
		}

		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: level == slog.LevelDebug,
			Level:     level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == "time" && a.Value.Kind() == slog.KindTime {
					return slog.Attr{}
				}
				return a
			},
		})))

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		slog.Info("kcptun", "version", VERSION)
		var listener net.Listener
		var isUnix bool
		if _, _, err := net.SplitHostPort(config.LocalAddr); err != nil {
			isUnix = true
		}
		if isUnix {
			addr, err := net.ResolveUnixAddr("unix", config.LocalAddr)
			checkError(err, "ResolveUnixAddr", "error", err)
			listener, err = net.ListenUnix("unix", addr)
			checkError(err, "ListenUnix", "error", err)
		} else {
			addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
			checkError(err, "ResolveTCPAddr", "error", err)
			listener, err = net.ListenTCP("tcp", addr)
			checkError(err, "ListenTCP", "error", err)
		}

		slog.Info("config", "smux version", config.SmuxVer)
		slog.Info("config", "listening addr", listener.Addr())
		slog.Info("config", "encryption", config.Crypt)
		slog.Info("config", "QPP", config.QPP)
		slog.Info("config", "QPP Count", config.QPPCount)
		slog.Info("config", "nodelay", config.NoDelay, "interval", config.Interval, "resend", config.Resend, "noCongestion", config.NoCongestion)
		slog.Info("config", "remote addresses", config.RemoteAddrs)
		slog.Info("config", "sndwnd", config.SndWnd, "rcvwnd", config.RcvWnd)
		slog.Info("config", "compression", !config.NoComp)
		slog.Info("config", "mtu", config.MTU)
		slog.Info("config", "ratelimit", config.RateLimit)
		slog.Info("config", "datashard", config.DataShard, "parityshard", config.ParityShard)
		slog.Info("config", "acknodelay", config.AckNodelay)
		slog.Info("config", "dscp", config.DSCP)
		slog.Info("config", "sockbuf", config.SockBuf)
		slog.Info("config", "smuxbuf", config.SmuxBuf)
		slog.Info("config", "framesize", config.FrameSize)
		slog.Info("config", "streambuf", config.StreamBuf)
		slog.Info("config", "keepalive", config.KeepAlive)
		slog.Info("config", "conn", config.Conn)
		slog.Info("config", "autoexpire", config.AutoExpire)
		slog.Info("config", "scavengettl", config.ScavengeTTL)
		slog.Info("config", "snmplog", config.SnmpLog)
		slog.Info("config", "snmpperiod", config.SnmpPeriod)
		slog.Info("config", "tcp", config.TCP)
		slog.Info("config", "pprof", config.Pprof)
		slog.Info("config", "conntrack", config.UseConntrack)
		if config.DNSConfig != nil {
			slog.Info("config", "local-ifname", config.DNSConfig.LocalInterfaceName)
		}

		var conntrackLookup ConntrackLookup
		if config.UseConntrack {
			localCIDR, err := GetRouteTable(config.DNSConfig.LocalInterfaceName)
			if err != nil {
				checkError(err, "GetRouteTable", "error", err)
			}

			_, ipNet, _ := net.ParseCIDR(localCIDR)

			cf, err := NewConntrackFlow([]ConnTupleKeyFilter{
				func(key ConnTupleKey) bool {
					return key.Proto != syscall.IPPROTO_TCP || key.Port == 53
				},
				func(key ConnTupleKey) bool {
					return !ipNet.Contains(net.ParseIP(key.Addr))
				},
			})
			if err != nil {
				checkError(err, "Create conntrack flow", "error", err)
			}
			conntrackLookup = cf
		}

		// QPP parameters check
		if config.QPP {
			minSeedLength := qpp.QPPMinimumSeedLength(8)
			if len(config.Key) < minSeedLength {
				color.Red("QPP Warning: 'key' has size of %d bytes, required %d bytes at least", len(config.Key), minSeedLength)
			}

			minPads := qpp.QPPMinimumPads(8)
			if config.QPPCount < minPads {
				color.Red("QPP Warning: QPPCount %d, required %d at least", config.QPPCount, minPads)
			}

			if new(big.Int).GCD(nil, nil, big.NewInt(int64(config.QPPCount)), big.NewInt(8)).Int64() != 1 {
				color.Red("QPP Warning: QPPCount %d, choose a prime number for security", config.QPPCount)
			}
		}

		// Scavenge parameters check
		if config.AutoExpire != 0 && config.ScavengeTTL > config.AutoExpire {
			color.Red("WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.")
			color.Red("Try limiting scavengettl to a smaller value.")
		}

		// SMUX Version check
		if config.SmuxVer > maxSmuxVer {
			checkError(errors.New("unsupported"), "smux version", config.SmuxVer)
		}

		slog.Info("initiating key derivation")
		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		slog.Info("key derivation done")
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "null":
			block = nil
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}

		createConn := func() (*smux.Session, error) {
			kcpconn, err := dial(&config, block)
			if err != nil {
				return nil, errors.Wrap(err, "dial()")
			}
			kcpconn.SetStreamMode(true)
			kcpconn.SetWriteDelay(false)
			kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
			kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
			kcpconn.SetMtu(config.MTU)
			kcpconn.SetACKNoDelay(config.AckNodelay)
			kcpconn.SetRateLimit(uint32(config.RateLimit))

			if err := kcpconn.SetDSCP(config.DSCP); err != nil {
				slog.Error("SetDSCP", "error", err)
			}
			if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
				slog.Error("SetReadBuffer", "error", err)
			}
			if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
				slog.Error("SetWriteBuffer", "error", err)
			}
			slog.Info("smux version", "version", config.SmuxVer, "localAddr", kcpconn.LocalAddr(), "remoteAddr", kcpconn.RemoteAddr())
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = config.SmuxVer
			smuxConfig.MaxReceiveBuffer = config.SmuxBuf
			smuxConfig.MaxStreamBuffer = config.StreamBuf
			smuxConfig.MaxFrameSize = config.FrameSize
			smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

			if err := smux.VerifyConfig(smuxConfig); err != nil {
				checkError(err, "VerifyConfig", "error", err)
			}

			// stream multiplex
			var session *smux.Session
			if config.NoComp {
				session, err = smux.Client(kcpconn, smuxConfig)
			} else {
				session, err = smux.Client(std.NewCompStream(kcpconn), smuxConfig)
			}
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			return session, nil
		}

		// wait until a connection is ready
		waitConn := func() *smux.Session {
			for {
				if session, err := createConn(); err == nil {
					return session
				} else {
					slog.Info("re-connecting", "error", err)
					time.Sleep(time.Second)
				}
			}
		}

		// start snmp logger
		go std.SnmpLogger(config.SnmpLog, config.SnmpPeriod)

		// start pprof
		if config.Pprof {
			go http.ListenAndServe(":6060", nil)
		}

		// start scavenger if autoexpire is set
		chScavenger := make(chan timedSession, 128)
		if config.AutoExpire > 0 {
			go scavenger(chScavenger, &config)
		}

		// start listener
		numconn := uint16(config.Conn)
		muxes := make([]timedSession, numconn)
		rr := uint16(0)

		// create shared QPP
		var _Q_ *qpp.QuantumPermutationPad
		if config.QPP {
			_Q_ = qpp.NewQPP([]byte(config.Key), uint16(config.QPPCount))
		}

		for {
			p1, err := listener.Accept()
			if err != nil {
				checkError(err, "Accept", "error", err)
			}
			idx := rr % numconn

			// do auto expiration && reconnection
			if muxes[idx].session == nil || muxes[idx].session.IsClosed() ||
				(config.AutoExpire > 0 && time.Now().After(muxes[idx].expiryDate)) {
				muxes[idx].session = waitConn()
				muxes[idx].expiryDate = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
				if config.AutoExpire > 0 { // only when autoexpire set
					chScavenger <- muxes[idx]
				}
			}

			go handleClient(_Q_, []byte(config.Key), muxes[idx].session, p1, config.Quiet, config.CloseWait, conntrackLookup)
			rr++
		}
	}
	myApp.Run(os.Args)
}

// handleClient aggregates connection p1 on mux
func handleClient(_Q_ *qpp.QuantumPermutationPad,
	seed []byte,
	session *smux.Session,
	p1 net.Conn,
	quiet bool,
	closeWait int,
	conntrackLookup ConntrackLookup) {
	// handles transport layer
	defer p1.Close()
	p2, err := session.OpenStream()
	if err != nil {
		slog.Debug("OpenStream", "error", err)
		return
	}
	defer p2.Close()

	slog.Debug("stream opened", "in", p1.RemoteAddr(), "out", p2.RemoteAddr(), "id", p2.ID())
	defer slog.Debug("stream closed", "in", p1.RemoteAddr(), "out", p2.RemoteAddr(), "id", p2.ID())

	var s1, s2 io.ReadWriteCloser = p1, p2
	// if QPP is enabled, create QPP read write closer
	if _Q_ != nil {
		// replace s2 with QPP port
		s2 = std.NewQPPPort(p2, _Q_, seed)
	}

	defer func() {
		s1.Close()
		s2.Close()
	}()

	// if conntrack is enabled, we need to send socks5 handshake before sending data
	if conntrackLookup != nil {
		from := p1.RemoteAddr().(*net.TCPAddr)

		slog.Debug("conntrack conns state", "src-ip", from.IP.String(), "src-port", from.Port)
		var to *net.TCPAddr

		func() {
			for range [3]int{} {
				to, err = conntrackLookup.GetConnsState(from)
				if err == nil {
					break
				}
				time.Sleep(time.Millisecond * 100)
			}

			if to == nil {
				slog.Warn("Fallback to direct connection", "error", err)
				return
			}
			slog.Debug("send socks5 connect request", "dst-ip", to.IP.String(), "dst-port", to.Port)
			// send socks5 handshake
			err = std.SendSocksConnectRequest(p2, to)
			if err != nil {
				slog.Debug("socks5 send handshake", "error", err)
				return
			}

			err = std.ReadSocksConnectResponse(p2)
			if err != nil {
				slog.Debug("socks5 read handshake", "error", err)
				return
			}
		}()
	}

	// stream layer
	err1, err2 := std.Pipe(s1, s2, closeWait)

	// handles transport layer errors
	if err1 != nil && err1 != io.EOF {
		slog.Debug("pipe", "error", err1, "in", p1.RemoteAddr(), "out", p2.RemoteAddr(), "id", p2.ID())
	}
	if err2 != nil && err2 != io.EOF {
		slog.Debug("pipe", "error", err2, "in", p1.RemoteAddr(), "out", p2.RemoteAddr(), "id", p2.ID())
	}
}

func checkError(err error, msg string, args ...any) {
	if err != nil {
		var pc uintptr
		var pcs [1]uintptr
		// skip [runtime.Callers, this function, this function's caller]
		runtime.Callers(2, pcs[:])
		pc = pcs[0]
		r := slog.NewRecord(time.Now(), slog.LevelError, msg, pc)
		r.Add(args...)
		slog.Default().Handler().Handle(context.Background(), r)
		os.Exit(-1)
	}
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

// scavenger goroutine is used to close expired sessions
func scavenger(ch chan timedSession, config *client.Config) {
	ticker := time.NewTicker(scavengePeriod * time.Second)
	defer ticker.Stop()
	var sessionList []timedSession
	for {
		select {
		case item := <-ch:
			sessionList = append(sessionList, timedSession{
				item.session,
				item.expiryDate.Add(time.Duration(config.ScavengeTTL) * time.Second)})
		case <-ticker.C:
			var newList []timedSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.IsClosed() {
					slog.Info("session normally closed", "addr", s.session.LocalAddr())
				} else if time.Now().After(s.expiryDate) {
					s.session.Close()
					slog.Info("session closed due to ttl", "addr", s.session.LocalAddr())
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}

func GetRouteTable(ifName string) (string, error) {
	// Get system routing rules
	routeFile, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("failed to open route file: %v", err)
	}
	defer routeFile.Close()

	scanner := bufio.NewScanner(routeFile)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			iface := fields[0]
			destHex := fields[1]
			maskHex := fields[7]

			if iface != ifName {
				continue
			}

			// Convert hex to IP address
			dest, _ := hex.DecodeString(destHex)
			mask, _ := hex.DecodeString(maskHex)
			cidr := net.IPNet{
				IP:   net.IPv4(dest[3], dest[2], dest[1], dest[0]),
				Mask: net.IPv4Mask(mask[3], mask[2], mask[1], mask[0]),
			}

			return cidr.String(), nil
		}
	}

	return "", nil
}
