//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type ConntrackFlow struct {
	conn    *conntrack.Conn
	evChan  chan conntrack.Event
	errCh   chan error
	conns   *ttlcache.Cache[ConnTupleKey, ConnTuple]
	filters []ConnTupleKeyFilter
}

type ConnTuple struct {
	Addr  net.IP
	Port  uint16
	Proto uint8
}

func NewConntrackFlow(filters []ConnTupleKeyFilter) (*ConntrackFlow, error) {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		slog.Error("Dial conntrack", "error", err)
		return nil, err
	}

	evChan := make(chan conntrack.Event, 1024)
	errCh, err := conn.Listen(evChan, 8, append(netfilter.GroupsCT, netfilter.GroupsCTExp...))
	if err != nil {
		slog.Error("Listen conntrack", "error", err)
		return nil, err
	}

	err = conn.SetOption(netlink.ListenAllNSID, true)
	if err != nil {
		slog.Error("Set option conntrack", "error", err)
		return nil, err
	}

	cf := &ConntrackFlow{
		conn:    conn,
		evChan:  evChan,
		errCh:   errCh,
		conns:   ttlcache.New(ttlcache.WithTTL[ConnTupleKey, ConnTuple](time.Minute)),
		filters: filters,
	}

	go cf.run()

	return cf, nil
}

func (cf *ConntrackFlow) run() {
	slog.Info("ConntrackFlow started")
	for {
	NEXT_LOOP:
		select {
		case err := <-cf.errCh:
			slog.Error("Flow error", "error", err)
		case ev := <-cf.evChan:
			switch {
			case ev.Type == conntrack.EventNew || ev.Type == conntrack.EventUpdate:
				key := ConnTupleKey{
					Addr:  ev.Flow.TupleOrig.IP.SourceAddress.String(),
					Port:  ev.Flow.TupleOrig.Proto.SourcePort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}

				for _, filter := range cf.filters {
					if filter(key) {
						goto NEXT_LOOP
					}
				}

				value := ConnTuple{
					Addr:  ev.Flow.TupleOrig.IP.DestinationAddress.AsSlice(),
					Port:  ev.Flow.TupleOrig.Proto.DestinationPort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}

				slog.Debug("conntrack assured",
					"src", key.Addr, "port", key.Port, "proto", key.Proto, "timeout", ev.Flow.Timeout)
				cf.conns.Set(key, value, time.Duration(ev.Flow.Timeout)*time.Second)
			case ev.Type == conntrack.EventDestroy:
				key := ConnTupleKey{
					Addr:  ev.Flow.TupleOrig.IP.SourceAddress.String(),
					Port:  ev.Flow.TupleOrig.Proto.SourcePort,
					Proto: ev.Flow.TupleOrig.Proto.Protocol,
				}

				for _, filter := range cf.filters {
					if filter(key) {
						goto NEXT_LOOP
					}
				}

				slog.Debug("conntrack die", "src", key.Addr, "port", key.Port, "proto", key.Proto)
				cf.conns.Delete(key)
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

	item := cf.conns.Get(key)
	if item == nil || item.IsExpired() {
		return nil, fmt.Errorf("conn not found")
	}

	return &net.TCPAddr{
		IP:   item.Value().Addr,
		Port: int(item.Value().Port),
	}, nil
}
