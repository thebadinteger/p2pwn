package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MainServer = "www.easy4ipcloud.com:8800"
	Version    = "5.0.0"
)

var ErrChannelAuthRequired = errors.New("p2p-channel requires authentication (code 403)")

func IsChannelAuthRequired(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrChannelAuthRequired) || strings.Contains(err.Error(), "p2p-channel requires authentication")
}

type DHClient struct {
	serial            string
	username          string
	userkey           string
	dtype             int
	randsalt          string
	p2pServerAddr     string
	relayAddr         string
	agentAddr         string
	deviceRAddr       string
	ptcpSession       *PTCPSession
	devicePTCPSession *PTCPSession // separate PTCP session for direct device path
	timeout           time.Duration
	retries           int

	// Connections
	mainConn   *net.UDPConn // main_remote
	deviceConn *net.UDPConn // device_remote

	aid         []byte // random aid
	sign        []byte // sign from relay
	cameraLAddr string // camera local addr

	deviceUser string
	devicePass string
	pwnedAuth  bool // true if type1 auth succeeded
}

func NewDHClient(serial string) *DHClient {
	return &DHClient{
		serial:   serial,
		username: DefaultUsername,
		userkey:  DefaultUserKey,
	}
}

func (c *DHClient) SetDeviceAuth(user, pass, randsalt string) {
	c.dtype = 1
	c.deviceUser = user
	c.devicePass = pass
	c.randsalt = randsalt
}

func (c *DHClient) GetDeviceAuth() (user, pass, randsalt string, isType1 bool) {
	return c.deviceUser, c.devicePass, c.randsalt, c.dtype > 0
}

func (c *DHClient) IsPwnedAuth() bool {
	return c.pwnedAuth
}

func newUDPConn() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *DHClient) sendTo(conn *net.UDPConn, addr string, data []byte) error {
	udpAddr, err := resolveCached(addr)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(data, udpAddr)
	return err
}

type DHResponse struct {
	Code    int
	Status  string
	Headers map[string]string
	Body    string
	XMLBody map[string]string
}

func parseDHResponse(data []byte) (*DHResponse, error) {
	text := string(data)
	parts := strings.SplitN(text, "\r\n\r\n", 2)
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid response: no header")
	}

	headerLines := strings.Split(parts[0], "\r\n")
	if len(headerLines) < 1 {
		return nil, fmt.Errorf("empty header")
	}
	statusParts := strings.SplitN(headerLines[0], " ", 3)
	if len(statusParts) < 2 {
		return nil, fmt.Errorf("invalid status line: %s", headerLines[0])
	}

	resp := &DHResponse{Headers: make(map[string]string)}
	code, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid code: %s", statusParts[1])
	}
	resp.Code = code
	if len(statusParts) > 2 {
		resp.Status = strings.Join(statusParts[2:], " ")
	}

	for _, line := range headerLines[1:] {
		if idx := strings.Index(line, ": "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+2:])
			resp.Headers[key] = value
		}
	}

	if len(parts) > 1 {
		resp.Body = strings.TrimSpace(parts[1])
		resp.XMLBody = parseXMLMap(parts[1])
	}

	return resp, nil
}

func parseXMLMap(xmlData string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(xmlData))
	var stack []string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				key := strings.Join(stack, "/")
				result[key] = text
			}
		}
	}
	return result
}

func (c *DHClient) doExchange(conn *net.UDPConn, addr, method, path, body string, auth bool, cseq uint32, timeout time.Duration, maxAttempts int) ([]byte, error) {
	prof := SmartPSSProfile
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		acseq := cseq
		if acseq == 0 {
			acseq = prof.nextCSeq()
		}
		req := prof.buildRequest(method, path, body, auth, acseq)
		if err := c.sendTo(conn, addr, req); err != nil {
			return nil, err
		}
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := conn.ReadFrom(buf)
		if err == nil {
			return buf[:n], nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("recvResend: no response after %d attempts (timeout=%v): %v", maxAttempts, timeout, lastErr)
}

type channelIdentity struct {
	identify string
	created  int64
	cseq     uint32
}

func (c *DHClient) newChannelIdentity(prof *CloudProfile) *channelIdentity {
	identify := make([]byte, 0, len(c.aid)*3-1)
	for i, b := range c.aid {
		if i > 0 {
			identify = append(identify, ' ')
		}
		identify = strconv.AppendInt(identify, int64(b>>4), 16)
		identify = strconv.AppendInt(identify, int64(b&0x0f), 16)
	}
	return &channelIdentity{identify: string(identify), created: time.Now().Unix(), cseq: prof.nextCSeq()}
}

// renders the p2p-channel XML for one crypto generation
func (c *DHClient) channelBody(id *channelIdentity, laddrPlain string) (body string, key []byte) {
	if c.dtype == 0 {
		return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr><version>%s</version></body>",
			id.identify, laddrPlain, Version), nil
	}
	if c.randsalt == "" {
		return "", nil
	}
	key = GetP2PKey(c.deviceUser, c.devicePass, c.randsalt)
	nonce := GetP2PNonce()
	encLaddr := GetP2PEnc(key, nonce, laddrPlain)
	authStr := GetP2PAuthAt(c.deviceUser, key, nonce, encLaddr, c.randsalt, id.created)
	return fmt.Sprintf("<body>%s<Identify>%s</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>%s</LocalAddr><version>%s</version></body>",
		authStr, id.identify, encLaddr, Version), key
}

func (c *DHClient) fetchRelayAgent(prof *CloudProfile, timeout time.Duration) (string, error) {
	respData, err := c.doExchange(c.mainConn, c.relayAddr, prof.verbFor(""), "/relay/agent", "", true, 0, timeout, 1)
	if err != nil {
		return "", fmt.Errorf("recv relay agent: %w", err)
	}
	resp, err := parseDHResponse(respData)
	if err != nil {
		return "", err
	}
	if resp.Code >= 300 {
		return "", fmt.Errorf("relay agent returned %d", resp.Code)
	}
	token := resp.XMLBody["body/Token"]
	c.agentAddr = resp.XMLBody["body/Agent"]
	if token == "" || c.agentAddr == "" {
		return "", fmt.Errorf("relay agent returned no token/agent")
	}
	return token, nil
}

func (c *DHClient) startRelayAgent(prof *CloudProfile, token string) {
	body := "<body><Client>:0</Client></body>"
	for i := 0; i < 3; i++ {
		req := prof.buildRequest(prof.verbFor(body), "/relay/start/"+token, body, true, prof.nextCSeq())
		if err := c.sendTo(c.mainConn, c.agentAddr, req); err != nil {
			return
		}
		c.mainConn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		buf := make([]byte, 4096)
		if _, _, err := c.mainConn.ReadFrom(buf); err == nil {
			return
		}
	}
}

// notifies the device about the allocated relay agent
func (c *DHClient) waitRelayChannelAck(prof *CloudProfile, body string, timeout time.Duration, maxAttempts int) error {
	path := "/device/" + c.serial + "/relay-channel"
	method := prof.verbFor(body)
	cseq := prof.nextCSeq()
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req := prof.buildRequest(method, path, body, true, cseq)
		if err := c.sendTo(c.mainConn, prof.MainServer, req); err != nil {
			return fmt.Errorf("relay-channel send: %w", err)
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			c.mainConn.SetReadDeadline(deadline)
			buf := make([]byte, 4096)
			n, _, rErr := c.mainConn.ReadFrom(buf)
			if rErr != nil {
				break // resend
			}
			relResp, pErr := parseDHResponse(buf[:n])
			if pErr != nil {
				continue
			}
			if relResp.Code == 200 {
				return nil
			}
			if relResp.Code >= 400 {
				if relResp.Code == 403 {
					return ErrChannelAuthRequired
				}
				return fmt.Errorf("relay-channel error %d: %s", relResp.Code, relResp.Body)
			}
		}
	}
	return fmt.Errorf("relay-channel timeout: no response received")
}

func (c *DHClient) Handshake() error {
	var err error
	var resp *DHResponse
	var respData []byte

	prof := SmartPSSProfile
	mainServer := prof.MainServer

	c.mainConn, err = newUDPConn()
	if err != nil {
		return fmt.Errorf("failed to create main conn: %w", err)
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	maxAttempts := c.retries
	if maxAttempts < 1 {
		maxAttempts = 3
	}

	// cloud discovery. warmup probe first
	if _, err := c.doExchange(c.mainConn, mainServer, prof.verbFor(""), prof.WarmupPath, "", prof.WarmupAuth, 0, timeout, maxAttempts); err != nil {
		return fmt.Errorf("probe p2psrv: %w", err)
	}

	respData, err = c.doExchange(c.mainConn, mainServer, prof.verbFor(""), "/online/p2psrv/"+c.serial, "", true, 0, timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv online p2psrv: %w", err)
	}
	resp, err = parseDHResponse(respData)
	if err != nil {
		return err
	}
	if resp.Code >= 300 {
		return fmt.Errorf("online p2psrv returned %d: %s", resp.Code, resp.Body)
	}
	c.p2pServerAddr = resp.XMLBody["body/US"]
	if c.p2pServerAddr == "" {
		return fmt.Errorf("no P2P server address in response")
	}

	// warm-up probes to the device P2P server
	p2pConn, err := newUDPConn()
	if err != nil {
		return fmt.Errorf("failed to create p2p conn: %w", err)
	}
	defer p2pConn.Close()

	if _, err := c.doExchange(p2pConn, c.p2pServerAddr, prof.verbFor(""), "/probe/device/"+c.serial, "", true, 0, timeout, maxAttempts); err != nil {
		return fmt.Errorf("recv probe device: %w", err)
	}

	infoData, err := c.doExchange(p2pConn, c.p2pServerAddr, prof.verbFor(""), "/info/device/"+c.serial, "", true, 0, timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv info device: %w", err)
	}
	if infoResp, err := parseDHResponse(infoData); err == nil {
		infoField := infoResp.XMLBody["body/Info"]
		if infoField == "" {
			if m, jerr := decodeInfoJSONMap([]byte(strings.TrimSpace(infoResp.Body))); jerr == nil {
				infoField = m["Info"]
			}
		}
		if infoField != "" {
			if plain, err := DecryptDevInfo(infoField); err == nil {
				if salt, err := decodeInfoRandSalt(plain); err == nil && salt != "" {
					if c.randsalt == "" {
						c.randsalt = salt
					}
				}
			}
		}
	}

	// relay dispatcher lookup
	respData, err = c.doExchange(c.mainConn, mainServer, prof.verbFor(""), "/online/relay", "", true, 0, timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv online relay: %w", err)
	}
	resp, err = parseDHResponse(respData)
	if err != nil {
		return err
	}
	if resp.Code >= 300 {
		return fmt.Errorf("online relay returned %d: %s", resp.Code, resp.Body)
	}
	c.relayAddr = resp.XMLBody["body/Address"]
	if c.relayAddr == "" {
		return fmt.Errorf("no relay address in response")
	}

	c.deviceConn, err = newUDPConn()
	if err != nil {
		return fmt.Errorf("failed to create device conn: %w", err)
	}

	// p2p-channel
	c.aid = make([]byte, 8)
	rand.Read(c.aid)
	id := c.newChannelIdentity(prof)

	devPort := c.deviceConn.LocalAddr().(*net.UDPAddr).Port
	bindIP := egressIP(mainServer)
	laddrPlain := buildLocalAddr(localAddrPrefixes(bindIP), bindIP, devPort)

	sendChannel := func() error {
		bodyXML, _ := c.channelBody(id, laddrPlain)
		if c.dtype > 0 && bodyXML == "" {
			return fmt.Errorf("type 1 auth requested but no randsalt received from device")
		}
		req := prof.buildRequest(prof.verbFor(bodyXML), "/device/"+c.serial+"/p2p-channel", bodyXML, true, id.cseq)
		return c.sendTo(c.deviceConn, mainServer, req)
	}

	if err := sendChannel(); err != nil {
		return fmt.Errorf("p2p-channel send: %w", err)
	}

	token, err := c.fetchRelayAgent(prof, 4*time.Second)
	if err != nil {
		return err
	}
	c.startRelayAgent(prof, token)

	chanAttempts := maxAttempts
	chanTimeout := timeout
	pcBuf := make([]byte, 4096)
	resp = nil
	for attempt := 0; attempt < chanAttempts; attempt++ {
		if attempt > 0 {
			if err := sendChannel(); err != nil {
				return fmt.Errorf("p2p-channel send: %w", err)
			}
		}
		c.deviceConn.SetReadDeadline(time.Now().Add(chanTimeout))
		for {
			n, _, rErr := c.deviceConn.ReadFrom(pcBuf)
			if rErr != nil {
				break // resend with fresh crypto
			}
			parsed, pErr := parseDHResponse(pcBuf[:n])
			if pErr != nil {
				continue
			}
			if parsed.Code == 100 {
				continue
			}
			resp = parsed
			break
		}
		if resp != nil {
			break
		}
	}
	if resp == nil {
		return fmt.Errorf("recv p2p-channel: no response after %d attempts (timeout=%v)", chanAttempts, chanTimeout)
	}

	if resp.Code >= 400 {
		if resp.Code == 403 {
			return ErrChannelAuthRequired
		}
		return fmt.Errorf("p2p-channel error %d: %s", resp.Code, resp.Body)
	}

	c.deviceRAddr = resp.XMLBody["body/PubAddr"]
	c.cameraLAddr = resp.XMLBody["body/LocalAddr"]
	if c.deviceRAddr == "" {
		return fmt.Errorf("no device address in p2p-channel response")
	}

	// decrypt camera local addr with nonce from response
	var chanKey []byte
	if c.dtype > 0 {
		chanKey = GetP2PKey(c.deviceUser, c.devicePass, c.randsalt)
		nonceStr := resp.XMLBody["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			c.cameraLAddr = GetP2PDec(chanKey, nonceVal, c.cameraLAddr)
		}
		c.pwnedAuth = true
	}

	relayAuthStr := ""
	if c.dtype > 0 {
		relayNonce := GetP2PNonce()
		relayAuthStr = GetP2PAuth(c.deviceUser, chanKey, relayNonce, "", c.randsalt)
	}
	relayChBody := fmt.Sprintf("<body>%s<agentAddr>%s</agentAddr></body>", relayAuthStr, c.agentAddr)
	_ = c.waitRelayChannelAck(prof, relayChBody, 2*time.Second, maxAttempts)

	if c.dtype == 0 {
		if err := c.PTCPHandshake(); err != nil {
			return fmt.Errorf("ptcp handshake: %w", err)
		}
	} else {
		if err := c.CompleteRelayHandshake(); err != nil {
			return fmt.Errorf("relay ptcp handshake: %w", err)
		}
	}

	return nil
}

func (c *DHClient) EstablishDirectP2P() error {
	if c.dtype == 0 && c.sign == nil {
		return fmt.Errorf("no sign from relay PTCP handshake")
	}
	if c.deviceRAddr == "" {
		return fmt.Errorf("no device public address")
	}
	if c.cameraLAddr == "" {
		return fmt.Errorf("no camera local address from p2p-channel response")
	}

	deviceAddr := c.deviceRAddr
	deviceHost, devicePortStr, _ := net.SplitHostPort(deviceAddr)
	devicePort, _ := strconv.Atoi(devicePortStr)
	deviceIP := net.ParseIP(deviceHost)

	invertedAid := make([]byte, 8)
	for i, b := range c.aid {
		invertedAid[i] = 0xFF - b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)

	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devicePort))
	copy(eaddr[2:6], deviceIP.To4())
	for i, b := range eaddr {
		eaddr[i] = 0xFF - b
	}

	pkt1 := make([]byte, 0, 44)
	pkt1 = append(pkt1, []byte{0xff, 0xfe, 0xff, 0xe7}...)
	pkt1 = append(pkt1, cookie...)
	pkt1 = append(pkt1, transID...)
	pkt1 = append(pkt1, []byte{0x7f, 0xd5, 0xff, 0xf7}...)
	pkt1 = append(pkt1, invertedAid...)
	pkt1 = append(pkt1, []byte{0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe}...)
	pkt1 = append(pkt1, eaddr...)

	targets := []string{c.cameraLAddr, deviceAddr}
	for _, target := range targets {
		c.sendTo(c.deviceConn, target, pkt1)
	}

	var stunResponse []byte
	var cameraDirectAddr string
	buf := make([]byte, 4096)
	c.deviceConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	deadline := time.Now().Add(2500 * time.Millisecond)
	attempt := 0

	for time.Now().Before(deadline) {
		n, respAddr, err := c.deviceConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					for _, target := range targets {
						c.sendTo(c.deviceConn, target, pkt1)
					}
				}
				c.deviceConn.SetReadDeadline(time.Now().Add(1 * time.Second))
				continue
			}
			break
		}
		if n < 4 {
			continue
		}
		data := buf[:n]
		magic := string(data[:4])

		if magic == "\xfe\xfe\xff\xe7" {
			stunResponse = data
			respHost := respAddr.(*net.UDPAddr).IP.String()
			respPort := respAddr.(*net.UDPAddr).Port
			cameraDirectAddr = net.JoinHostPort(respHost, strconv.Itoa(respPort))
			break
		} else if magic == "\xff\xfe\xff\xe7" {
			// Cross-STUN init from device
			if n >= 40 {
				resp := make([]byte, 0, 40)
				resp = append(resp, []byte{0xfe, 0xfe, 0xff, 0xe7}...)
				resp = append(resp, data[4:8]...)
				resp = append(resp, data[8:20]...)
				resp = append(resp, []byte{0x7f, 0xd6, 0xff, 0xf7}...)
				resp = append(resp, invertedAid...)
				resp = append(resp, []byte{0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe}...)
				resp = append(resp, data[34:40]...)
				c.sendTo(c.deviceConn, respAddr.String(), resp)
			}
		}
	}

	if stunResponse == nil {
		return fmt.Errorf("inverted stun: no response received")
	}

	c.deviceRAddr = cameraDirectAddr
	deviceAddr = cameraDirectAddr

	// Send STUN confirm
	confirm := make([]byte, 0, 28)
	confirm = append(confirm, []byte{0xfe, 0xfe, 0xff, 0xf3}...)
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7f, 0xd6, 0xff, 0xf7}...)
	confirm = append(confirm, invertedAid...)

	for i := 0; i < 5; i++ {
		c.sendTo(c.deviceConn, deviceAddr, confirm)
	}

	time.Sleep(300 * time.Millisecond)
	c.deviceConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		_, _, err := c.deviceConn.ReadFrom(buf)
		if err != nil {
			break
		}
	}
	c.deviceConn.SetReadDeadline(time.Time{})

	c.devicePTCPSession = NewPTCPSession()

	synPkt := c.devicePTCPSession.Send(MakeSYNBody())
	if err := c.sendTo(c.deviceConn, deviceAddr, synPkt.Serialize()); err != nil {
		return fmt.Errorf("direct ptcp syn: %w", err)
	}

	c.deviceConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := c.deviceConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("direct ptcp syn-ack: %w", err)
	}
	synAck, pErr := ParsePTCPPacket(buf[:n])
	if pErr != nil {
		return pErr
	}
	c.devicePTCPSession.Receive(synAck)

	if c.dtype == 0 {
		authBody := MakeAuthReqBody(c.sign)
		authPkt := c.devicePTCPSession.Send(authBody)
		if err := c.sendTo(c.deviceConn, deviceAddr, authPkt.Serialize()); err != nil {
			return fmt.Errorf("direct ptcp auth: %w", err)
		}

		c.deviceConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err = c.deviceConn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("direct ptcp auth response: %w", err)
		}
		authResp, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil {
			return pErr
		}
		c.devicePTCPSession.Receive(authResp)
		authOK := false
		if len(authResp.Body) > 0 && authResp.Body[0] == 0x1A {
			authOK = true
		}
		if !authOK && len(authResp.Body) == 0 {
			c.deviceConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err = c.deviceConn.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("direct ptcp auth retry: %w", err)
			}
			authResp, pErr = ParsePTCPPacket(buf[:n])
			if pErr != nil {
				return pErr
			}
			c.devicePTCPSession.Receive(authResp)
			if len(authResp.Body) > 0 && authResp.Body[0] == 0x1A {
				authOK = true
			}
		}

		finalBody := MakeFinalBody()
		finalPkt := c.devicePTCPSession.Send(finalBody)
		if err := c.sendTo(c.deviceConn, deviceAddr, finalPkt.Serialize()); err != nil {
			return fmt.Errorf("direct ptcp final: %w", err)
		}

		c.deviceConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err = c.deviceConn.ReadFrom(buf)
		if err == nil {
			finalResp, pErr := ParsePTCPPacket(buf[:n])
			if pErr == nil {
				c.devicePTCPSession.Receive(finalResp)
			}
		}
	} else {
		ackPkt := c.devicePTCPSession.Send([]byte{})
		c.sendTo(c.deviceConn, deviceAddr, ackPkt.Serialize())
	}
	return nil
}

func (c *DHClient) PTCPHandshake() error {
	c.ptcpSession = NewPTCPSession()
	agentConn := c.mainConn

	synPkt := c.ptcpSession.Send(MakeSYNBody())
	if err := c.sendTo(agentConn, c.agentAddr, synPkt.Serialize()); err != nil {
		return fmt.Errorf("ptcp syn: %w", err)
	}

	var sign []byte
	readAttempts := 0
	for {
		agentConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, _, err := agentConn.ReadFrom(buf)
		if err != nil {
			if readAttempts > 3 {
				return fmt.Errorf("ptcp timeout reading sign: %w", err)
			}
			readAttempts++
			continue
		}
		pkt, pErr := ParsePTCPPacket(buf[:n])
		if pErr != nil {
			continue
		}
		c.ptcpSession.Receive(pkt)

		bt := byte(0)
		if len(pkt.Body) > 0 {
			bt = pkt.Body[0]
		}

		if bt == 0x00 && len(pkt.Body) == 4 {
			synPkt2 := c.ptcpSession.Send(MakeSYNBody())
			c.sendTo(agentConn, c.agentAddr, synPkt2.Serialize())
			continue
		}

		if len(pkt.Body) > 12 {
			sign = pkt.Body[12:]
			c.sign = sign
			break
		}
		break
	}

	if sign == nil {
		signReq := MakeSignReqBody()
		signPkt := c.ptcpSession.Send(signReq)
		c.sendTo(agentConn, c.agentAddr, signPkt.Serialize())

		for attempts := 0; attempts < 5; attempts++ {
			agentConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			n, _, err := agentConn.ReadFrom(buf)
			if err != nil {
				continue
			}
			pkt, pErr := ParsePTCPPacket(buf[:n])
			if pErr != nil {
				continue
			}
			c.ptcpSession.Receive(pkt)
			if len(pkt.Body) > 12 {
				sign = pkt.Body[12:]
				c.sign = sign
				break
			}
		}
	}

	if sign == nil {
		return fmt.Errorf("could not get sign from device/agent")
	}

	ackPkt := c.ptcpSession.Send([]byte{})
	c.sendTo(agentConn, c.agentAddr, ackPkt.Serialize())

	return nil
}

func (c *DHClient) CompleteRelayHandshake() error {
	if c.agentAddr == "" {
		return fmt.Errorf("no relay agent address")
	}

	agentConn := c.mainConn
	buf := make([]byte, 4096)

	if c.dtype > 0 {
		if c.ptcpSession != nil {
			return nil
		}
		c.ptcpSession = NewPTCPSession()
		synPkt := c.ptcpSession.Send(MakeSYNBody())
		if err := c.sendTo(agentConn, c.agentAddr, synPkt.Serialize()); err != nil {
			return fmt.Errorf("relay ptcp syn send: %w", err)
		}

		deadline := time.Now().Add(6 * time.Second)
		agentConn.SetReadDeadline(deadline)

		for time.Now().Before(deadline) {
			n, _, err := agentConn.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("relay ptcp syn-ack read: %w", err)
			}
			pkt, pErr := ParsePTCPPacket(buf[:n])
			if pErr != nil {
				continue
			}
			c.ptcpSession.Receive(pkt)
			if isSYNBody(pkt.Body) || (len(pkt.Body) == 4 && pkt.Body[0] == 0x00) {
				// Received SYN-ACK. send ACK then a heartbeat
				ackPkt := c.ptcpSession.Send([]byte{})
				c.sendTo(agentConn, c.agentAddr, ackPkt.Serialize())

				// Send the 0x13 heartbeat
				hbPkt := c.ptcpSession.Send(MakeHeartbeatBody())
				c.sendTo(agentConn, c.agentAddr, hbPkt.Serialize())
				return nil
			}
		}
		return fmt.Errorf("relay ptcp timeout waiting for syn-ack")
	}

	if c.sign == nil {
		return fmt.Errorf("no sign from relay PTCP handshake")
	}

	authBody := MakeAuthReqBody(c.sign)
	authPkt := c.ptcpSession.Send(authBody)
	if err := c.sendTo(agentConn, c.agentAddr, authPkt.Serialize()); err != nil {
		return fmt.Errorf("relay auth send: %w", err)
	}

	agentConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := agentConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("relay auth response: %w", err)
	}
	authResp, pErr := ParsePTCPPacket(buf[:n])
	if pErr != nil {
		return pErr
	}
	c.ptcpSession.Receive(authResp)
	if len(authResp.Body) == 0 || authResp.Body[0] != 0x1A {
		return fmt.Errorf("relay auth failed: body[0]=0x%02x", bodyByte(authResp.Body))
	}

	finalBody := MakeFinalBody()
	finalPkt := c.ptcpSession.Send(finalBody)
	if err := c.sendTo(agentConn, c.agentAddr, finalPkt.Serialize()); err != nil {
		return fmt.Errorf("relay final send: %w", err)
	}

	agentConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = agentConn.ReadFrom(buf)
	if err == nil {
		finalResp, pErr := ParsePTCPPacket(buf[:n])
		if pErr == nil {
			c.ptcpSession.Receive(finalResp)
		}
	}

	return nil
}

func bodyByte(body []byte) byte {
	if len(body) == 0 {
		return 0
	}
	return body[0]
}

func (c *DHClient) StartHeartbeat(stop chan struct{}) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if c.ptcpSession != nil && c.mainConn != nil && c.agentAddr != "" {
					hb := MakeHeartbeatBody()
					pkt := c.ptcpSession.Send(hb)
					c.mainConn.WriteTo(pkt.Serialize(), parseUDPAddr(c.agentAddr))
				}
				if c.devicePTCPSession != nil && c.deviceConn != nil && c.deviceRAddr != "" {
					hb := MakeHeartbeatBody()
					pkt := c.devicePTCPSession.Send(hb)
					c.deviceConn.WriteTo(pkt.Serialize(), parseUDPAddr(c.deviceRAddr))
				}
			case <-stop:
				return
			}
		}
	}()
}

func (c *DHClient) SetTimeout(d time.Duration) {
	c.timeout = d
}

func (c *DHClient) SetRetries(n int) {
	c.retries = n
}

func (c *DHClient) Close() {
	if c.mainConn != nil {
		c.mainConn.Close()
	}
	if c.deviceConn != nil {
		c.deviceConn.Close()
	}
}

func (c *DHClient) GetDeviceAddr() string {
	return c.deviceRAddr
}

var (
	dnsPools   sync.Map
	dnsPoolTTL = 5 * time.Minute
)

func parseUDPAddr(addr string) *net.UDPAddr {
	udpAddr, err := resolveCached(addr)
	if err != nil {
		return nil
	}
	return udpAddr
}

func resolveCached(hostport string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil || net.ParseIP(host) != nil {
		return net.ResolveUDPAddr("udp", hostport)
	}
	if v, ok := dnsPools.Load(hostport); ok {
		if p := v.(*dnsPool); time.Now().Before(p.expires) && len(p.addrs) > 0 {
			i := p.next.Add(1)
			return p.addrs[int(i)%len(p.addrs)], nil
		}
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return net.ResolveUDPAddr("udp", hostport)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(ips) == 0 {
		return net.ResolveUDPAddr("udp", hostport)
	}
	addrs := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if ip.IP == nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{IP: ip.IP, Port: port})
	}
	if len(addrs) == 0 {
		return net.ResolveUDPAddr("udp", hostport)
	}
	p := &dnsPool{addrs: addrs, expires: time.Now().Add(dnsPoolTTL)}
	dnsPools.Store(hostport, p)
	i := p.next.Add(1)
	return addrs[int(i)%len(addrs)], nil
}

type dnsPool struct {
	addrs   []*net.UDPAddr
	next    atomic.Uint32
	expires time.Time
}

// does serial resolves on the cloud and answers the probe
func CheckOnline(serial string) bool {
	return checkOnlineWith(serial, 2*time.Second, 2)
}

func checkOnlineWith(serial string, timeout time.Duration, retries int) bool {
	prof := SmartPSSProfile

	buildReq := func(body, path string) string {
		return string(prof.buildRequest(prof.verbFor(body), path, body, true, prof.nextCSeq()))
	}

	mainConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return false
	}
	defer mainConn.Close()

	sendRecv := func(conn *net.UDPConn, addr string, reqData string, maxAttempts int) ([]byte, bool) {
		buf := make([]byte, 4096)
		udpAddr, err := resolveCached(addr)
		if err != nil || udpAddr == nil {
			return nil, false
		}
		for i := 0; i < maxAttempts; i++ {
			conn.WriteTo([]byte(reqData), udpAddr)
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := conn.ReadFrom(buf)
			if err == nil {
				return buf[:n], true
			}
		}
		return nil, false
	}

	sendRecvConn := func(addr, reqData string, maxAttempts int) ([]byte, bool) {
		udpAddr, err := resolveCached(addr)
		if err != nil || udpAddr == nil {
			return nil, false
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, false
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for i := 0; i < maxAttempts; i++ {
			conn.Write([]byte(reqData))
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, err := conn.Read(buf)
			if err == nil {
				return buf[:n], true
			}
		}
		return nil, false
	}

	// no warmup probe here
	req1 := buildReq("", "/online/p2psrv/"+serial)
	respData, ok := sendRecv(mainConn, prof.MainServer, req1, retries)
	if !ok {
		return false
	}

	resp, err := parseDHResponse(respData)
	if err != nil || resp.Code >= 300 {
		return false
	}
	p2pAddr := resp.XMLBody["body/US"]
	if p2pAddr == "" {
		return false
	}

	req2 := buildReq("", "/probe/device/"+serial)
	respData, ok = sendRecvConn(p2pAddr, req2, retries)
	if !ok {
		return false
	}

	resp, err = parseDHResponse(respData)
	if err != nil {
		return false
	}

	return resp.Code == 200
}
