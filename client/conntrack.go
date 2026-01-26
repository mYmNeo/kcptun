package main

import (
	"net"
)

// When use conntrack, you should add some iptables rules to allow the connection
// 1. -A PREROUTING -s <src ips optional> -i <in-if> -p tcp -j DNAT --to-destination <kcptun listen address>
// example: -A PREROUTING -s 192.168.1.107/32 -i eth0 -p tcp -j DNAT --to-destination 192.168.1.108:8888
// 2. -A POSTROUTING -s <dhcp-range> -j MASQUERADE
// example: -A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE

type ConnTupleKey struct {
	Addr  string
	Port  uint16
	Proto uint8
}

type ConnTupleKeyFilter func(key ConnTupleKey) bool

type ConntrackLookup interface {
	GetConnsState(src *net.TCPAddr) (*net.TCPAddr, error)
}
