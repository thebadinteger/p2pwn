package p2p

// camera ports from the /info/device Info blob

import (
	"strconv"
	"strings"
	"sync"
)

const (
	DefaultHTTPPort = 80
	DefaultPrivPort = 37777
	DefaultRTSPPort = 554
)

type camPorts struct {
	http int
	priv int
	rtsp int
}

var camPortsMu sync.RWMutex
var camPortsBySerial = make(map[string]camPorts)

func validCamPort(v int) bool {
	return v >= 1 && v <= 65535
}

func atoiPort(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || !validCamPort(v) {
		return 0
	}
	return v
}

func parseCamPorts(blobFields, topFields map[string]string) (http, priv, rtsp int) {
	merged := make(map[string]string, len(topFields)+len(blobFields))
	for k, v := range topFields {
		merged[strings.TrimPrefix(k, "body/")] = v
	}
	for k, v := range blobFields {
		merged[k] = v
	}
	return atoiPort(merged["httpport"]), atoiPort(merged["privport"]), atoiPort(merged["rtspport"])
}

// cache blob ports per serial. called on every handshake
func rememberCamPorts(serial string, http, priv, rtsp int) {
	if serial == "" {
		return
	}
	camPortsMu.Lock()
	camPortsBySerial[serial] = camPorts{http: http, priv: priv, rtsp: rtsp}
	camPortsMu.Unlock()
}

// return known camera ports for a serial (0 = unknown = default)
func CamPorts(serial string) (http, priv, rtsp int) {
	camPortsMu.RLock()
	p, ok := camPortsBySerial[serial]
	camPortsMu.RUnlock()
	if !ok {
		return 0, 0, 0
	}
	return p.http, p.priv, p.rtsp
}

// try-port lists: default first, blob custom second (deduped)
func HTTPTryPorts(serial string) []int {
	return tryPorts(DefaultHTTPPort, camPortHTTP(serial))
}

func PrivTryPorts(serial string) []int {
	return tryPorts(DefaultPrivPort, camPortPriv(serial))
}

func RTSPTryPorts(serial string) []int {
	return tryPorts(DefaultRTSPPort, camPortRTSP(serial))
}

func tryPorts(def, custom int) []int {
	if validCamPort(custom) && custom != def {
		return []int{def, custom}
	}
	return []int{def}
}

func camPortHTTP(serial string) int {
	h, _, _ := CamPorts(serial)
	return h
}

func camPortPriv(serial string) int {
	_, p, _ := CamPorts(serial)
	return p
}

func camPortRTSP(serial string) int {
	_, _, r := CamPorts(serial)
	return r
}

// serial comes from the client back-reference
func (t *PTCPTunnel) serial() string {
	if t == nil || t.client == nil {
		return ""
	}
	return t.client.serial
}

func (t *PTCPTunnel) customHTTPPort() int {
	h, _, _ := CamPorts(t.serial())
	if validCamPort(h) && h != DefaultHTTPPort {
		return h
	}
	return 0
}

func (t *PTCPTunnel) privTryPorts() []int {
	return PrivTryPorts(t.serial())
}

func (t *PTCPTunnel) httpTryPorts() []int {
	return HTTPTryPorts(t.serial())
}

func (t *PTCPTunnel) HTTPTryPorts() []int {
	return t.httpTryPorts()
}
