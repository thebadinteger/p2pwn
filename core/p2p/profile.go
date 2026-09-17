package p2p

// Easy4IP cloud parameters

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CloudProfile struct {
	MainServer string
	WSSEUser   string
	WSSEKey    string
	VerbGet    string
	VerbPost   string

	WarmupPath string
	WarmupAuth bool
}

var SmartPSSProfile = &CloudProfile{
	MainServer: MainServer,
	WSSEUser:   DefaultUsername,
	WSSEKey:    DefaultUserKey,
	VerbGet:    "DHGET",
	VerbPost:   "DHPOST",
	WarmupPath: "/probe/p2psrv",
	WarmupAuth: true,
}

var smartpssCSeqMu sync.Mutex
var smartpssCSeq uint32

func (p *CloudProfile) nextCSeq() uint32 {
	smartpssCSeqMu.Lock()
	defer smartpssCSeqMu.Unlock()
	smartpssCSeq++
	return smartpssCSeq
}

func wsseDigest(nonce, created, user, userkey string) string {
	h := sha1.Sum([]byte(nonce + created + "DHP2P:" + user + ":" + userkey))
	return base64.StdEncoding.EncodeToString(h[:])
}

func (p *CloudProfile) createdNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func wsseNonce() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return strconv.FormatInt(n.Int64()-(1<<31), 10)
}

func (p *CloudProfile) buildRequest(method, path, body string, auth bool, cseq uint32) []byte {
	nonceStr := wsseNonce()
	created := p.createdNow()
	digest := wsseDigest(nonceStr, created, p.WSSEUser, p.WSSEKey)

	authBlock := ""
	if auth {
		authBlock = fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
			p.WSSEUser, digest, nonceStr, created,
		)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, cseq))
	sb.WriteString(authBlock)
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))
	return []byte(sb.String())
}

// derives the request verb from the body presence
func (p *CloudProfile) verbFor(body string) string {
	if body != "" {
		return p.VerbPost
	}
	return p.VerbGet
}

func egressIP(hostport string) string {
	if c, err := net.Dial("udp4", hostport); err == nil {
		defer c.Close()
		if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
			return addr.IP.String()
		}
	}
	return "127.0.0.1"
}

func localAddrPrefixes(bindIP string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
			if s := ip4.String(); s != bindIP {
				out = append(out, s)
			}
		}
	}
	return out
}

func buildLocalAddr(prefixes []string, bindIP string, lport int) string {
	last := bindIP + ":" + strconv.Itoa(lport)
	if len(prefixes) == 0 {
		return bindIP + "," + last
	}
	return strings.Join(prefixes, ",") + "," + last
}

func decodeInfoJSONMap(plain []byte) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(string(plain)))
	dec.UseNumber()
	typed := map[string]any{}
	if err := dec.Decode(&typed); err != nil {
		return nil, fmt.Errorf("info json: %v", err)
	}
	out := make(map[string]string, len(typed))
	for k, v := range typed {
		switch val := v.(type) {
		case string:
			out[k] = val
		case json.Number:
			out[k] = val.String()
		case bool:
			out[k] = strconv.FormatBool(val)
		}
	}
	return out, nil
}

func decodeInfoRandSalt(plain []byte) (string, error) {
	fields, err := decodeInfoJSONMap(plain)
	if err != nil {
		return "", err
	}
	if fields["randsalt"] == "" {
		return "", fmt.Errorf("randsalt absent from the Info blob")
	}
	return fields["randsalt"], nil
}
