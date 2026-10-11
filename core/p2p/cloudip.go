package p2p

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cloudCacheTTL = 10 * time.Minute
	cloudDNSWait  = 5 * time.Second
)

var cloudFallbackIPs = []string{
	"165.154.165.8",
	"165.154.165.15",
	"165.154.165.19",
	"165.154.165.21",
	"165.154.165.27",
	"165.154.165.33",
	"165.154.165.35",
	"165.154.165.37",
	"165.154.165.40",
	"165.154.165.41",
	"165.154.165.42",
	"165.154.165.43",
	"165.154.165.47",
	"165.154.165.48",
	"165.154.165.53",
	"165.154.165.79",
	"165.154.165.110",
	"165.154.165.154",
	"165.154.165.162",
	"165.154.165.163",
	"165.154.165.178",
}

type cloudPool struct {
	host    string
	port    int
	addrs   []*net.UDPAddr
	expires time.Time
}

var (
	cloudMu      sync.Mutex
	cloudCached  *cloudPool
	cloudRR      atomic.Uint32
	cloudFromDNS atomic.Bool
)

func trimCloudPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func isCloudHost(hostport string) bool {
	h := strings.ToLower(trimCloudPort(hostport))
	return h == "www.easy4ipcloud.com" || h == "easy4ipcloud.com"
}

func cloudStaticAddrs(port int) []*net.UDPAddr {
	out := make([]*net.UDPAddr, 0, len(cloudFallbackIPs))
	for _, ip := range cloudFallbackIPs {
		if v := net.ParseIP(ip).To4(); v != nil {
			out = append(out, &net.UDPAddr{IP: v, Port: port})
		}
	}
	return out
}

func cloudDNSAddrs(host string, port int) []*net.UDPAddr {
	ctx, cancel := context.WithTimeout(context.Background(), cloudDNSWait)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			out = append(out, &net.UDPAddr{IP: v4, Port: port})
		}
	}
	return out
}

func cloudRehydrate(hostport string) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 {
		return
	}
	addrs := cloudDNSAddrs(host, port)
	if len(addrs) == 0 {
		return
	}
	cloudMu.Lock()
	cloudCached = &cloudPool{host: hostport, port: port, addrs: addrs, expires: time.Now().Add(cloudCacheTTL)}
	cloudFromDNS.Store(true)
	cloudMu.Unlock()
}

func CloudAddrs(hostport string) []*net.UDPAddr {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 {
		return nil
	}

	cloudMu.Lock()
	defer cloudMu.Unlock()
	if cloudCached != nil && cloudCached.host == hostport && time.Now().Before(cloudCached.expires) && len(cloudCached.addrs) > 0 {
		return cloudCached.addrs
	}

	if addrs := cloudDNSAddrs(host, port); len(addrs) > 0 {
		cloudCached = &cloudPool{host: hostport, port: port, addrs: addrs, expires: time.Now().Add(cloudCacheTTL)}
		cloudFromDNS.Store(true)
		return addrs
	}

	if !isCloudHost(hostport) {
		return nil
	}
	fallback := cloudStaticAddrs(port)
	if len(fallback) == 0 {
		return nil
	}
	cloudCached = &cloudPool{host: hostport, port: port, addrs: fallback, expires: time.Now().Add(cloudCacheTTL)}
	if !cloudFromDNS.Load() {
		LogDebugf("dns", "cloud dns unavailable using %d static fallback ips", len(fallback))
		go cloudRehydrate(hostport)
	}
	return fallback
}

func CloudNext(hostport string) *net.UDPAddr {
	addrs := CloudAddrs(hostport)
	if len(addrs) == 0 {
		return nil
	}
	return addrs[int(cloudRR.Add(1))%len(addrs)]
}
