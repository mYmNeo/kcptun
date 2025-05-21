package dns

type DNSConfig struct {
	UseDNS             bool     `json:"use-dns"`
	UseCache           bool     `json:"use-cache"`
	LocalInterfaceName string   `json:"local-ifname"`
	LocalProtocol      string   `json:"local-protocol"`
	LocalDNSPort       int      `json:"local-port"`
	RemoteDNSAddr      string   `json:"remote-dns-addr"`
	ForwardDNSAddr     string   `json:"forward-dns-addr"`
	GFWListURLs        []string `json:"gfwlist-urls"`
	GFWListFiles       []string `json:"gfwlist-files"`
	BlockedListFiles   []string `json:"blockedlist-files"`
	CacheTTL           int      `json:"cache-ttl"`
	IPTablesPath       string   `json:"iptables-path"`
	QPSLimit           int      `json:"qps-limit"`
	BurstLimit         int      `json:"burst-limit"`
	ConnPoolSize       int      `json:"pool-size"`
	Mode               string   `json:"mode"`
}
