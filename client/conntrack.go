package main

import (
	"net"
)

type ConntrackLookup interface {
	GetConnsState(src, dst *net.TCPAddr) (bool, error)
}
