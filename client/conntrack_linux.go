//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type ConntrackFlow struct {
	conn   *conntrack.Conn
	evChan chan conntrack.Event
	errCh  chan error
	l      sync.RWMutex
	conns  map[ConnTuple]struct{}
}

type ConnTuple struct {
	SrcAddr net.Addr
	DstAddr net.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func NewConntrackFlow() (*ConntrackFlow, error) {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		log.Printf("Dial conntrack failed: %v", err)
		return nil, err
	}

	evChan := make(chan conntrack.Event, 1024)
	errCh, err := conn.Listen(evChan, 1, append(netfilter.GroupsCT, netfilter.GroupsCTExp...))
	if err != nil {
		log.Printf("Listen conntrack failed: %v", err)
		return nil, err
	}

	err = conn.SetOption(netlink.ListenAllNSID, true)
	if err != nil {
		log.Printf("Set option conntrack failed: %v", err)
		return nil, err
	}

	cf := &ConntrackFlow{
		conn:   conn,
		evChan: evChan,
		errCh:  errCh,
		conns:  make(map[ConnTuple]struct{}),
	}

	go cf.run()

	return cf, nil
}

func (cf *ConntrackFlow) run() {
	log.Printf("ConntrackFlow started")
	for {
		select {
		case err := <-cf.errCh:
			log.Printf("Error: %v", err)
		case ev := <-cf.evChan:
			switch {
			case ev.Flow.Status.Assured():
				key := ConnTuple{
					SrcAddr: &net.IPAddr{IP: ev.Flow.TupleOrig.IP.SourceAddress.AsSlice()},
					DstAddr: &net.IPAddr{IP: ev.Flow.TupleOrig.IP.DestinationAddress.AsSlice()},
					SrcPort: ev.Flow.TupleOrig.Proto.SourcePort,
					DstPort: ev.Flow.TupleOrig.Proto.DestinationPort,
					Proto:   ev.Flow.TupleOrig.Proto.Protocol,
				}
				cf.l.Lock()
				if _, ok := cf.conns[key]; !ok {
					cf.conns[key] = struct{}{}
				}
				cf.l.Unlock()
			case ev.Flow.Status.Dying():
				key := ConnTuple{
					SrcAddr: &net.IPAddr{IP: ev.Flow.TupleOrig.IP.SourceAddress.AsSlice()},
					DstAddr: &net.IPAddr{IP: ev.Flow.TupleOrig.IP.DestinationAddress.AsSlice()},
					SrcPort: ev.Flow.TupleOrig.Proto.SourcePort,
					DstPort: ev.Flow.TupleOrig.Proto.DestinationPort,
					Proto:   ev.Flow.TupleOrig.Proto.Protocol,
				}
				cf.l.Lock()
				delete(cf.conns, key)
				cf.l.Unlock()
			}
		}
	}
}

func (cf *ConntrackFlow) GetConnsState(src, dst *net.TCPAddr) (bool, error) {
	key := ConnTuple{
		SrcAddr: src,
		DstAddr: dst,
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Proto:   uint8(syscall.IPPROTO_TCP),
	}

	cf.l.RLock()
	defer cf.l.RUnlock()

	_, ok := cf.conns[key]
	if !ok {
		return false, fmt.Errorf("conn not found")
	}

	return true, nil
}
