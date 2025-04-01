package std

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/OneYX/v2ray-core/tools/gfwlist"
	"github.com/coreos/go-iptables/iptables"
	"github.com/jellydator/ttlcache/v3"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	cfg_dns "github.com/xtaci/kcptun/config/dns"
)

const (
	GFW_IPLIST = "gfw_iplist"
)

// DNSServer represents a DNS server
type DNSServer struct {
	server    *dns.Server
	client    DNSClient
	localIP   string
	localCIDR string
	proxyPort string

	gfwList     *gfwlist.GFWList
	recordCache *ttlcache.Cache[dns.Question, *DNSCache]

	routerRules RouterRules
	dnsConfig   *cfg_dns.DNSConfig
}

type DNSClient struct {
	limiter  *rate.Limiter
	cli      *dns.Client
	remoteIP string
	pool     *ConnPool
}

type ConnPool struct {
	lock    sync.Mutex
	conns   map[*dns.Conn]bool
	maxConn int
	builder func() *dns.Conn
}

func (cp *ConnPool) GetConn() (conn *dns.Conn) {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	for c, used := range cp.conns {
		if used {
			continue
		}

		cp.conns[c] = true
		conn = c
		return
	}

	if len(cp.conns)+1 > cp.maxConn {
		slog.Error("Exceeded max connection limit", "maxConn", cp.maxConn)
		return nil
	}

	conn = cp.builder()
	if conn == nil {
		return nil
	}

	cp.conns[conn] = true

	return conn
}

func (cp *ConnPool) PutConn(conn *dns.Conn) {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	cp.conns[conn] = false
}

func (cp *ConnPool) Free(conn *dns.Conn) {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	conn.Close()
	delete(cp.conns, conn)
}

type RouterRules struct {
	ipt *iptables.IPTables
	// dns
	dnsRule []string
	// prerouting
	preRoutingRule []string
	// postrouting
	postRoutingRule []string
}

type DNSCache struct {
	record     []dns.RR
	lastUpdate time.Time
}

func parseAddress(addr string) (network string, host string, err error) {
	// Check if the address contains a network specification
	if strings.Contains(addr, "://") {
		parts := strings.SplitN(addr, "://", 2)
		network = parts[0]
		host = parts[1]
		return
	}

	return "", "", fmt.Errorf("invalid address format: %s, expected host:port", addr)
}

// NewDNSServer creates a new DNS server
func NewDNSServer(cfg *cfg_dns.DNSConfig, kcpListenAddr string) (*DNSServer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("dns config is nil")
	}

	localIP, err := GetIPFromInterface(cfg.LocalInterfaceName)
	if err != nil {
		return nil, err
	}

	localCIDR, err := GetRouteTable(cfg.LocalInterfaceName)
	if err != nil {
		return nil, err
	}

	server := &DNSServer{
		server: &dns.Server{
			Addr:          fmt.Sprintf("%s:%d", localIP, cfg.LocalDNSPort),
			Net:           cfg.LocalProtocol,
			MaxTCPQueries: -1,
		},
		recordCache: ttlcache.New(
			ttlcache.WithTTL[dns.Question, *DNSCache](time.Duration(cfg.CacheTTL)*time.Second),
			ttlcache.WithDisableTouchOnHit[dns.Question, *DNSCache](),
		),
		dnsConfig: cfg,
		localIP:   localIP,
		localCIDR: localCIDR,
	}

	if len(kcpListenAddr) > 0 {
		_, port, err := net.SplitHostPort(kcpListenAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid kcp listen address: %s", err)
		}

		server.proxyPort = port
	}

	if cfg.RemoteDNSAddr != "" {
		remoteNetwork, remoteIP, err := parseAddress(cfg.RemoteDNSAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid remote address: %s", err)
		}
		server.client.remoteIP = remoteIP
		server.client.cli = &dns.Client{
			Net:     remoteNetwork,
			UDPSize: dns.MaxMsgSize,
			Dialer: &net.Dialer{
				Timeout: 10 * time.Second,
			},
		}
		server.client.pool = &ConnPool{
			builder: func() *dns.Conn {
				conn, err := server.client.cli.Dial(remoteIP)
				if err != nil {
					slog.Error("Failed to create dns connection", "error", err)
					return nil
				}

				return conn
			},
			conns:   make(map[*dns.Conn]bool),
			maxConn: cfg.ConnPoolSize,
		}
		server.client.limiter = rate.NewLimiter(rate.Limit(cfg.QPSLimit), cfg.BurstLimit)

		gfwList, err := gfwlist.NewGFWList(cfg.GFWListURLs, cfg.GFWListFiles)
		if err != nil {
			return nil, fmt.Errorf("failed to create gfwlist: %s", err)
		}
		server.gfwList = gfwList
	}

	dns.HandleFunc(".", server.handleDNSRequest)

	return server, nil
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

func (s *DNSServer) PrepareDNSRules() error {
	ipt, err := iptables.New(iptables.Path(s.dnsConfig.IPTablesPath), iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}

	dnsRule := []string{
		"-s", s.localCIDR,
		"-p", "udp",
		"--dport", "53",
		"-j", "DNAT",
		"--to-destination", s.server.Addr,
	}
	err = ipt.AppendUnique("nat", "PREROUTING", dnsRule...)
	if err != nil {
		return fmt.Errorf("failed to create dns iptables: %s", err)
	}
	s.routerRules.dnsRule = dnsRule
	if s.routerRules.ipt == nil {
		s.routerRules.ipt = ipt
	}

	return nil
}

func (s *DNSServer) PrepareGFWListIPSet() error {
	out, err := exec.Command("ipset", "create", GFW_IPLIST, "hash:ip", "-exist").CombinedOutput()
	if err != nil {
		slog.Error("Create ipset", "ipset", GFW_IPLIST, "output", string(out))
		return err
	}

	gfwlistRule := []string{
		"-p", "tcp",
		"-m", "set",
		"--match-set", GFW_IPLIST,
		"dst",
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(s.localIP, s.proxyPort),
	}

	ipt, err := iptables.New(iptables.Path(s.dnsConfig.IPTablesPath), iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	if s.routerRules.ipt == nil {
		s.routerRules.ipt = ipt
	}

	err = ipt.AppendUnique("nat", "PREROUTING", gfwlistRule...)
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	s.routerRules.preRoutingRule = gfwlistRule

	postRoutingRule := []string{
		"-s", s.localCIDR,
		"-j", "MASQUERADE",
	}
	err = ipt.AppendUnique("nat", "POSTROUTING", postRoutingRule...)
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	s.routerRules.postRoutingRule = postRoutingRule

	return nil
}

func (s *DNSServer) AddGFWFilterIP(answers []dns.RR) {
	for _, ans := range answers {
		// Extract IP address from DNS answer record
		switch rr := ans.(type) {
		case *dns.A:
			// Handle IPv4 address
			ip := rr.A.String()
			slog.Info("Adding IPv4 to GFW filter", "ip", ip)
			_, err := exec.Command("ipset", "add", GFW_IPLIST, ip, "-exist").CombinedOutput()
			if err != nil {
				slog.Error("Failed to add IP to ipset", "ip", ip, "error", err)
			}
		}
	}
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	RegisterExitHandler(s.cleanRules)
	slog.Info("Init router rules")

	if !s.ListenerOnly() {
		err := s.PrepareGFWListIPSet()
		if err != nil {
			return fmt.Errorf("failed to prepare gfwlist ipset: %s", err)
		}

		err = s.PrepareDNSRules()
		if err != nil {
			return fmt.Errorf("failed to prepare dns rules: %s", err)
		}
	}

	if s.recordCache != nil {
		s.recordCache.OnEviction(func(ctx context.Context, er ttlcache.EvictionReason, i *ttlcache.Item[dns.Question, *DNSCache]) {
			maxDuration := time.Duration(s.dnsConfig.CacheTTL*2) * time.Second
			if i.Value().lastUpdate.Add(maxDuration).Before(time.Now()) {
				return
			}

			question := i.Key()
			resolver := s.resolveDNS
			blocked := s.isBlocked(question.Name)

			if blocked {
				resolver = s.resolveFromRemote
			}

			answer := resolver(question)
			if answer == nil {
				return
			}

			val := i.Value()
			val.record = answer
			s.recordCache.Set(question, val, ttlcache.DefaultTTL)

			if blocked {
				s.AddGFWFilterIP(answer)
			}
		})

		go s.recordCache.Start()
	}

	return s.server.ListenAndServe()
}

func (s *DNSServer) cleanRules() {
	slog.Info("Cleaning router rules")
	if s.routerRules.ipt != nil {
		if len(s.routerRules.dnsRule) > 0 {
			s.routerRules.ipt.DeleteIfExists("nat", "PREROUTING", s.routerRules.dnsRule...)
		}

		if len(s.routerRules.preRoutingRule) > 0 {
			s.routerRules.ipt.DeleteIfExists("nat", "PREROUTING", s.routerRules.preRoutingRule...)
		}

		if len(s.routerRules.postRoutingRule) > 0 {
			s.routerRules.ipt.DeleteIfExists("nat", "POSTROUTING", s.routerRules.postRoutingRule...)
		}
	}

	exec.Command("ipset", "flush", GFW_IPLIST).CombinedOutput()
	exec.Command("ipset", "destroy", GFW_IPLIST).CombinedOutput()
}

// Stop stops the DNS server
func (s *DNSServer) Stop() error {
	s.cleanRules()
	return s.server.Shutdown()
}

func (s *DNSServer) ListenerOnly() bool {
	return s.client.cli == nil && s.dnsConfig.Mode == "server"
}

// handleDNSRequest handles incoming DNS requests
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true

	// Resolve the DNS query
	for _, q := range r.Question {
		answer := s.recordCache.Get(q)
		if answer != nil && !answer.IsExpired() {
			val := answer.Value()
			val.lastUpdate = time.Now()

			m.Answer = append(m.Answer, val.record...)
			continue
		}

		slog.Info("DNS Query", "name", q.Name, "type", dns.TypeToString[q.Qtype])
		if s.ListenerOnly() || !s.isBlocked(q.Name) {
			answer := s.resolveDNS(q)
			if answer == nil {
				continue
			}
			val := &DNSCache{
				record:     answer,
				lastUpdate: time.Now(),
			}
			s.recordCache.Set(q, val, ttlcache.DefaultTTL)
			m.Answer = append(m.Answer, answer...)
		} else {
			slog.Debug("GFW Blocked", "name", q.Name)
			answer := s.resolveFromRemote(q)
			if answer == nil {
				continue
			}
			val := &DNSCache{
				record:     answer,
				lastUpdate: time.Now(),
			}
			s.recordCache.Set(q, val, ttlcache.DefaultTTL)
			s.AddGFWFilterIP(answer)
			m.Answer = append(m.Answer, answer...)
		}
	}

	if err := w.WriteMsg(m); err != nil {
		slog.Error("Writing DNS response", "error", err)
	}
}

func (s *DNSServer) isBlocked(domain string) bool {
	return s.gfwList.IsBlockedByGFW(strings.TrimSuffix(domain, "."))
}

func (s *DNSServer) resolveDNS(q dns.Question) []dns.RR {
	answers := make([]dns.RR, 0)
	switch q.Qtype {
	case dns.TypeA:
		// Try to resolve the A record
		ips, err := net.LookupIP(strings.TrimSuffix(q.Name, "."))
		if err == nil {
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					rr := &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    uint32(s.dnsConfig.CacheTTL),
						},
						A: ipv4,
					}
					answers = append(answers, rr)
				}
			}
		}
	case dns.TypeAAAA:
		// Try to resolve the AAAA record
		ips, err := net.LookupIP(strings.TrimSuffix(q.Name, "."))
		if err == nil {
			for _, ip := range ips {
				if ipv6 := ip.To16(); ipv6 != nil && ip.To4() == nil {
					rr := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    uint32(s.dnsConfig.CacheTTL),
						},
						AAAA: ipv6,
					}
					answers = append(answers, rr)
				}
			}
		}
	case dns.TypeMX:
		// Try to resolve MX records
		mxs, err := net.LookupMX(strings.TrimSuffix(q.Name, "."))
		if err == nil {
			for _, mx := range mxs {
				rr := &dns.MX{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    uint32(s.dnsConfig.CacheTTL),
					},
					Preference: uint16(mx.Pref),
					Mx:         mx.Host,
				}
				answers = append(answers, rr)
			}
		}
	case dns.TypeTXT:
		// Try to resolve TXT records
		txts, err := net.LookupTXT(strings.TrimSuffix(q.Name, "."))
		if err == nil {
			for _, txt := range txts {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    uint32(s.dnsConfig.CacheTTL),
					},
					Txt: []string{txt},
				}
				answers = append(answers, rr)
			}
		}
	}

	return answers
}

func (s *DNSServer) resolveFromRemote(q dns.Question) []dns.RR {
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)
	req.RecursionDesired = true
	req.SetEdns0(dns.MaxMsgSize, true)

	s.client.limiter.Wait(context.Background())
	slog.Debug("Remote DNS Query", "name", q.Name, "type", dns.TypeToString[q.Qtype])
	var (
		resp *dns.Msg
		err  error
	)

	// try max 3 times
	for range [3]int{} {
		conn := s.client.pool.GetConn()
		if conn == nil {
			slog.Error("Failed to get connection from pool")
			err = errors.New("get connection from pool")
			time.Sleep(time.Second)
			continue
		}

		resp, _, err = s.client.cli.ExchangeWithConn(req, conn)
		if err == nil {
			s.client.pool.PutConn(conn)
			break
		}

		s.client.pool.Free(conn)
		if err != io.EOF {
			slog.Error("DNS query", "error", err)
		}
	}

	if err != nil {
		return nil
	}

	if resp.Rcode != dns.RcodeSuccess {
		slog.Error("Resolve from remote", "error", dns.RcodeToString[resp.Rcode])
		return nil
	}

	return resp.Answer
}
