module github.com/xtaci/kcptun

require (
	github.com/OneYX/v2ray-core v0.0.0
	github.com/coreos/go-iptables v0.8.0
	github.com/fatih/color v1.18.0
	github.com/golang/snappy v1.0.0
	github.com/jellydator/ttlcache/v3 v3.4.0
	github.com/mdlayher/netlink v1.8.0
	github.com/miekg/dns v1.1.68
	github.com/pkg/errors v0.9.1
	github.com/ti-mo/conntrack v0.5.2
	github.com/ti-mo/netfilter v0.5.3
	github.com/urfave/cli v1.22.17
	github.com/vishvananda/netlink v1.3.1
	github.com/xtaci/kcp-go/v5 v5.6.24
	github.com/xtaci/qpp v1.1.18
	github.com/xtaci/smux v1.5.35
	github.com/xtaci/tcpraw v1.2.31
	golang.org/x/crypto v0.41.0
	golang.org/x/time v0.11.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.5 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)

replace (
	github.com/OneYX/v2ray-core => ./staging/github.com/OneYX/v2ray-core
	github.com/xtaci/tcpraw => ./staging/github.com/xtaci/tcpraw
)

go 1.24.1

toolchain go1.24.2
