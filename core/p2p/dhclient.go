package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	return errors.Is(err, ErrChannelAuthRequired) || strings.Contains(err.Error(), "403")
}

type DHClient struct {
	serial        string
	username      string
	userkey       string
	p2pServerAddr string
	relayAddr     string
	agentAddr     string
	deviceLAddr   string
	deviceRAddr   string
	ptcpSession   *PTCPSession
	devicePTCPSession *PTCPSession // separate PTCP session for direct device path
	cseq          int
	lport         int
	timeout       time.Duration
	retries       int

	// Connections
	mainConn    *net.UDPConn  // main_remote
	deviceConn  *net.UDPConn  // device_remote

	aid         []byte // random aid
	sign        []byte // sign from relay
	cameraLAddr string // camera local addr
}

func NewDHClient(serial string, debug bool) *DHClient {
	return &DHClient{
		serial:   serial,
		username: DefaultUsername,
		userkey:  DefaultUserKey,
	}
}

func (c *DHClient) newUDPConn() (*net.UDPConn, int, error) {
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil, 0, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, 0, err
	}
	lport := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, lport, nil
}

func (c *DHClient) sendTo(conn *net.UDPConn, addr string, data []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
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

func (c *DHClient) buildRequest(method, path, body string) string {
	c.cseq++
	auth := NewWSSEAuth(c.username, c.userkey)
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("CSeq: ")
	sb.WriteString(strconv.Itoa(c.cseq))
	sb.WriteString("\r\n")
	sb.WriteString(auth.Header())
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString("Content-Type: \r\n")
		sb.WriteString("Content-Length: ")
		sb.WriteString(strconv.Itoa(len(body)))
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

func (c *DHClient) Handshake() error {
	var err error
	var resp *DHResponse
	var respData []byte

	c.mainConn, c.lport, err = c.newUDPConn()
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

	req := c.buildRequest("DHGET", "/probe/p2psrv", "")
	if err := c.sendTo(c.mainConn, MainServer, []byte(req)); err != nil {
		return fmt.Errorf("probe p2psrv: %w", err)
	}
	if _, err := c.recvResend(c.mainConn, MainServer, []byte(req), timeout, maxAttempts); err != nil {
		return fmt.Errorf("recv probe p2psrv: %w", err)
	}

	req = c.buildRequest("DHGET", "/online/p2psrv/"+c.serial, "")
	if err := c.sendTo(c.mainConn, MainServer, []byte(req)); err != nil {
		return fmt.Errorf("online p2psrv: %w", err)
	}
	respData, err = c.recvResend(c.mainConn, MainServer, []byte(req), timeout, maxAttempts)
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

	req = c.buildRequest("DHGET", "/online/relay", "")
	if err := c.sendTo(c.mainConn, MainServer, []byte(req)); err != nil {
		return fmt.Errorf("online relay: %w", err)
	}
	respData, err = c.recvResend(c.mainConn, MainServer, []byte(req), timeout, maxAttempts)
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

	p2pConn, _, err := c.newUDPConn()
	if err != nil {
		return fmt.Errorf("failed to create p2p conn: %w", err)
	}
	defer p2pConn.Close()

	devCseq := c.cseq
	makeDevReq := func(method, path string) string {
		devCseq++
		auth := NewWSSEAuth(c.username, c.userkey)
		return method + " " + path + " HTTP/1.1\r\n" +
			"CSeq: " + strconv.Itoa(devCseq) + "\r\n" +
			auth.Header() + "\r\n\r\n"
	}

	req2 := makeDevReq("DHGET", "/probe/device/"+c.serial)
	c.sendTo(p2pConn, c.p2pServerAddr, []byte(req2))
	_, err = c.recvResend(p2pConn, c.p2pServerAddr, []byte(req2), timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv probe device: %w", err)
	}

	req2 = makeDevReq("DHGET", "/info/device/"+c.serial)
	c.sendTo(p2pConn, c.p2pServerAddr, []byte(req2))
	_, err = c.recvResend(p2pConn, c.p2pServerAddr, []byte(req2), timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv info device: %w", err)
	}

	c.deviceConn, _, err = c.newUDPConn()
	if err != nil {
		return fmt.Errorf("failed to create device conn: %w", err)
	}

	c.aid = make([]byte, 8)
	rand.Read(c.aid)
	identify := make([]byte, 0, len(c.aid)*3-1)
	for i, b := range c.aid {
		if i > 0 {
			identify = append(identify, ' ')
		}
		identify = strconv.AppendInt(identify, int64(b>>4), 16)
		identify = strconv.AppendInt(identify, int64(b&0x0f), 16)
	}

	laddr := fmt.Sprintf("127.0.0.1:%d", c.deviceConn.LocalAddr().(*net.UDPAddr).Port)
	c.deviceLAddr = laddr

	ipaddr := fmt.Sprintf("<IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr>", laddr)
	bodyXML := fmt.Sprintf("<body><Identify>%s</Identify>%s<version>%s</version></body>",
		string(identify), ipaddr, Version)

	pcReq := c.buildRequest("DHPOST", "/device/"+c.serial+"/p2p-channel", bodyXML)
	if err := c.sendTo(c.deviceConn, MainServer, []byte(pcReq)); err != nil {
		return fmt.Errorf("p2p-channel send: %w", err)
	}

	relReq := c.buildRequest("DHGET", "/relay/agent", "")
	if err := c.sendTo(c.mainConn, c.relayAddr, []byte(relReq)); err != nil {
		return fmt.Errorf("relay agent: %w", err)
	}
	respData, err = c.recvResend(c.mainConn, c.relayAddr, []byte(relReq), timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv relay agent: %w", err)
	}
	resp, err = parseDHResponse(respData)
	if err != nil {
		return err
	}
	if resp.Code >= 300 {
		return fmt.Errorf("relay agent returned %d", resp.Code)
	}
	token := resp.XMLBody["body/Token"]
	c.agentAddr = resp.XMLBody["body/Agent"]

	relStartReq := c.buildRequest("DHPOST", "/relay/start/"+token, "<body><Client>:0</Client></body>")
	if err := c.sendTo(c.mainConn, c.agentAddr, []byte(relStartReq)); err != nil {
		return fmt.Errorf("relay start: %w", err)
	}
	_, err = c.recvResend(c.mainConn, c.agentAddr, []byte(relStartReq), timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv relay start: %w", err)
	}

	respData, err = c.recvResend(c.deviceConn, MainServer, []byte(pcReq), timeout, maxAttempts)
	if err != nil {
		return fmt.Errorf("recv p2p-channel: %w", err)
	}
	resp, err = parseDHResponse(respData)
	if err != nil {
		return err
	}

	if resp.Code == 100 {
		respData, err = c.recvResend(c.deviceConn, MainServer, []byte(pcReq), timeout, maxAttempts)
		if err != nil {
			return fmt.Errorf("recv p2p-channel 2: %w", err)
		}
		resp, err = parseDHResponse(respData)
		if err != nil {
			return err
		}
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

	rcBody := fmt.Sprintf("<body><agentAddr>%s</agentAddr></body>", c.agentAddr)
	rcReq := c.buildRequest("DHPOST", "/device/"+c.serial+"/relay-channel", rcBody)
	if err := c.sendTo(c.mainConn, MainServer, []byte(rcReq)); err != nil {
		return fmt.Errorf("relay-channel send: %w", err)
	}

	c.recvResend(c.mainConn, MainServer, []byte(rcReq), timeout, maxAttempts)

	return nil
}

func (c *DHClient) EstablishDirectP2P() error {
	if c.sign == nil {
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
	c.deviceConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	deadline := time.Now().Add(10 * time.Second)
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
				c.deviceConn.SetReadDeadline(time.Now().Add(2 * time.Second))
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

	// Send STUN confirm (0xfe 0xfe 0xff 0xf3) 5 times
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
	if c.sign == nil {
		return fmt.Errorf("no sign from relay PTCP handshake")
	}

	agentConn := c.mainConn

	authBody := MakeAuthReqBody(c.sign)
	authPkt := c.ptcpSession.Send(authBody)
	if err := c.sendTo(agentConn, c.agentAddr, authPkt.Serialize()); err != nil {
		return fmt.Errorf("relay auth send: %w", err)
	}

	agentConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
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

func (c *DHClient) recvResend(conn *net.UDPConn, addr string, reqData []byte, attemptTimeout time.Duration, maxAttempts int) ([]byte, error) {
	buf := make([]byte, 8192)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 && reqData != nil {
			c.sendTo(conn, addr, reqData)
		}
		conn.SetReadDeadline(time.Now().Add(attemptTimeout))
		n, _, err := conn.ReadFrom(buf)
		if err == nil {
			return buf[:n], nil
		}
	}
	return nil, fmt.Errorf("recvResend: no response after %d attempts (timeout=%v)", maxAttempts, attemptTimeout)
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

func parseUDPAddr(addr string) *net.UDPAddr {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	return udpAddr
}

func CheckOnline(serial string) bool {
	return checkOnlineWith(serial, 2*time.Second, 2)
}

func checkOnlineWith(serial string, timeout time.Duration, retries int) bool {
	mainConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return false
	}
	defer mainConn.Close()

	cseq := 0
	buildReq := func(method, path string) string {
		cseq++
		auth := NewWSSEAuth(DefaultUsername, DefaultUserKey)
		return method + " " + path + " HTTP/1.1\r\n" +
			"CSeq: " + strconv.Itoa(cseq) + "\r\n" +
			auth.Header() + "\r\n\r\n"
	}

	sendRecv := func(conn *net.UDPConn, addr string, reqData string, maxAttempts int) ([]byte, bool) {
		buf := make([]byte, 4096)
		udpAddr := parseUDPAddr(addr)
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

	req1 := buildReq("DHGET", "/online/p2psrv/"+serial)
	respData, ok := sendRecv(mainConn, MainServer, req1, retries)
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

	probeConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return false
	}
	defer probeConn.Close()

	req2 := buildReq("DHGET", "/probe/device/"+serial)
	respData, ok = sendRecv(probeConn, p2pAddr, req2, retries)
	if !ok {
		return false
	}

	resp, err = parseDHResponse(respData)
	if err != nil {
		return false
	}

	return resp.Code == 200
}

