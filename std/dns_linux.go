//go:build linux

package std

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func GetIPFromInterface(iferName string) (string, error) {
	nlHandle, err := netlink.NewHandle()
	if err != nil {
		return "", fmt.Errorf("failed to create netlink handle: %s", err)
	}
	defer nlHandle.Close()

	link, err := nlHandle.LinkByName(iferName)
	if err != nil {
		return "", fmt.Errorf("failed to get link by name: %s", err)
	}

	addrs, err := nlHandle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to get address list: %s", err)
	}

	for _, addr := range addrs {
		if !addr.IP.IsLoopback() {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				return ipv4.String(), nil
			}
		}
	}

	return "", fmt.Errorf("interface not found: %s", iferName)
}
