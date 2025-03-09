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
	conns  map[ConnTupleKey]ConnTuple
}

type ConnTuple struct {
	Addr  net.IP
	Port  uint16
	Proto uint8
}

type ConnTupleKey struct {
	Addr  string
	Port  uint16
	Proto uint8
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
		conns:  make(map[ConnTupleKey]ConnTuple),
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
				if ev.Flow.TupleOrig.Proto.Protocol != syscall.IPPROTO_TCP {
					continue
				}

				key := ConnTupleKey{
					Addr:  ev.Flow.TupleOrig.IP.SourceAddress.String(),
					Port:  ev.Flow.TupleOrig.Proto.SourcePort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}
				value := ConnTuple{
					Addr:  ev.Flow.TupleOrig.IP.DestinationAddress.AsSlice(),
					Port:  ev.Flow.TupleOrig.Proto.DestinationPort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}

				cf.l.Lock()
				if _, ok := cf.conns[key]; !ok {
					cf.conns[key] = value
				}
				cf.l.Unlock()
			case ev.Flow.Status.Dying():
				if ev.Flow.TupleOrig.Proto.Protocol != syscall.IPPROTO_TCP {
					continue
				}

				key := ConnTupleKey{
					Addr:  ev.Flow.TupleOrig.IP.SourceAddress.String(),
					Port:  ev.Flow.TupleOrig.Proto.SourcePort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}

				cf.l.Lock()
				delete(cf.conns, key)
				cf.l.Unlock()
			}
		}
	}
}

func (cf *ConntrackFlow) GetConnsState(src *net.TCPAddr) (*net.TCPAddr, error) {
	key := ConnTupleKey{
		Addr:  src.IP.String(),
		Port:  uint16(src.Port),
		Proto: uint8(syscall.IPPROTO_TCP),
	}

	cf.l.RLock()
	defer cf.l.RUnlock()

	val, ok := cf.conns[key]
	if !ok {
		return nil, fmt.Errorf("conn not found")
	}

	return &net.TCPAddr{
		IP:   val.Addr,
		Port: int(val.Port),
	}, nil
}
