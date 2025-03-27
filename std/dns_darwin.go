//go:build darwin

package std

import (
	"fmt"
	"net"
)

func GetIPFromInterface(iferName string) (string, error) {
	ifnames, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %s", err)
	}

	for _, ifname := range ifnames {
		if ifname.Name == iferName {
			addrs, err := ifname.Addrs()
			if err != nil {
				return "", fmt.Errorf("failed to get interface addresses: %s", err)
			}

			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipv4 := ipnet.IP.To4(); ipv4 != nil {
						return ipv4.String(), nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("interface not found: %s", iferName)
}
