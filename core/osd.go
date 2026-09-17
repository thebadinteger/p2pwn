package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/thebadinteger/p2pwn/core/p2p"
)

func normalizeOSDLines(custom []string) []string {
	var out []string
	for _, l := range custom {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if r := []rune(l); len(r) > 32 {
			l = string(r[:32])
		}
		out = append(out, l)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func normalizeOSDChannel(channel string) string {
	channel = strings.TrimSpace(channel)
	if r := []rune(channel); len(r) > 32 {
		channel = string(r[:32])
	}
	return channel
}

func pipeJoin(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	padded := make([]string, 5)
	copy(padded[5-len(lines):], lines)
	return strings.Join(padded, "|")
}

var bottomBoxRect = []int{5321, 7450, 7931, 7868}

func setIfExists(m map[string]any, key string, val any) {
	if _, ok := m[key]; ok {
		m[key] = val
	}
}

func buildTitleSet(vwTable, ctTable []any, channel string, lines []string) (ctOut, vwOut []any) {
	if channel != "" {
		if len(ctTable) == 0 {
			ctOut = []any{map[string]any{"Name": channel}}
		} else {
			ctOut = make([]any, 0, len(ctTable))
			for _, raw := range ctTable {
				if _, ok := raw.(map[string]any); ok {
					ctOut = append(ctOut, map[string]any{"Name": channel})
				}
			}
		}
	}
	if channel == "" && len(lines) == 0 {
		return ctOut, nil
	}
	text := pipeJoin(lines)
	for _, raw := range vwTable {
		m, ok := raw.(map[string]any)
		if !ok {
			vwOut = append(vwOut, raw)
			continue
		}
		if w, ok := m["ChannelTitle"].(map[string]any); ok {
			w["EncodeBlend"] = true
			w["PreviewBlend"] = true
		}
		if covers, ok := m["Covers"].([]any); ok {
			for _, c := range covers {
				if cm, ok := c.(map[string]any); ok {
					cm["EncodeBlend"] = false
					cm["PreviewBlend"] = false
				}
			}
		}
		if ct, ok := m["CustomTitle"].([]any); ok && len(ct) > 0 {
			idx := 1
			if idx >= len(ct) {
				idx = 0
			}
			for j := range ct {
				sm, ok := ct[j].(map[string]any)
				if !ok {
					continue
				}
				if len(lines) > 0 && j == idx {
					sm["Text"] = text
					sm["EncodeBlend"] = true
					sm["PreviewBlend"] = true
					setIfExists(sm, "TextAlign", 2)
					sm["Rect"] = append([]int(nil), bottomBoxRect...)
				} else {
					sm["Text"] = ""
					sm["EncodeBlend"] = false
					sm["PreviewBlend"] = false
				}
			}
		}
		vwOut = append(vwOut, m)
	}
	return ctOut, vwOut
}

func dhipGetTable(dhip *p2p.DHIPClient, name string, id int) ([]any, error) {
	r, err := dhip.Call("configManager.getConfig", map[string]any{"name": name}, id, nil, nil)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result false (%v)", name, r["error"])
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return nil, fmt.Errorf("getConfig %s: no params", name)
	}
	switch t := params["table"].(type) {
	case []any:
		return t, nil
	case map[string]any:
		return []any{t}, nil
	default:
		return nil, fmt.Errorf("getConfig %s: unexpected table shape", name)
	}
}

type rpc2ConnSession struct {
	tunnel     *p2p.PTCPTunnel
	realm      uint32
	reqTimeout time.Duration
}

func newRPC2Conn(tunnel *p2p.PTCPTunnel) (*rpc2ConnSession, func(), error) {
	realm := rand.Uint32()
	if err := tunnel.DoBindToPort(realm, 80); err != nil {
		return nil, nil, fmt.Errorf("rpc2 bind port 80: %w", err)
	}
	c := &rpc2ConnSession{tunnel: tunnel, realm: realm, reqTimeout: 15 * time.Second}
	return c, func() { tunnel.DisconnectRealm(realm) }, nil
}

func (c *rpc2ConnSession) post(path string, payload map[string]any, cookie string) (map[string]any, string, error) {
	raw, _ := json.Marshal(payload)
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", path, len(raw))
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	sb.WriteString("\r\n")
	sb.WriteString(string(raw))

	resp, err := c.tunnel.DoHTTPOnRealm(c.realm, []byte(sb.String()), c.reqTimeout)
	if err != nil {
		return nil, "", err
	}
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, "", fmt.Errorf("POST %s: malformed HTTP response", path)
	}
	headers, body := string(resp[:idx]), bytes.TrimSpace(resp[idx+4:])
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		status := headers
		if i := strings.Index(status, "\r\n"); i >= 0 {
			status = status[:i]
		}
		return nil, "", fmt.Errorf("POST %s: bad JSON body (status: %s)", path, status)
	}
	return out, headers, nil
}

func rpc2SessionCookie(headers string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "set-cookie:") {
			continue
		}
		val := strings.TrimSpace(line[len("set-cookie:"):])
		if i := strings.Index(val, ";"); i >= 0 {
			val = val[:i]
		}
		if strings.HasPrefix(val, "DhWebClientSessionID=") {
			return val
		}
	}
	return ""
}

func rpc2GetTable(conn *rpc2ConnSession, sess any, cookie, name string, id int) ([]any, error) {
	r, _, err := conn.post("/RPC2", map[string]any{
		"method":  "configManager.getConfig",
		"params":  map[string]any{"name": name},
		"id":      id,
		"session": sess,
	}, cookie)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result false (%v)", name, r["error"])
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		if arr, ok := r["params"].([]any); ok {
			return arr, nil
		}
		return nil, fmt.Errorf("getConfig %s: no params", name)
	}
	switch t := params["table"].(type) {
	case []any:
		return t, nil
	case map[string]any:
		return []any{t}, nil
	default:
		return nil, fmt.Errorf("getConfig %s: unexpected table shape", name)
	}
}

func newRPC2Session(tunnel *p2p.PTCPTunnel, login, pass string) (*osdSession, error) {
	conn, closeConn, err := newRPC2Conn(tunnel)
	if err != nil {
		return nil, err
	}

	emptyLogin := func(id int) (map[string]any, string, error) {
		return conn.post("/RPC2_Login", map[string]any{
			"method": "global.login",
			"params": map[string]any{
				"userName":   login,
				"password":   "",
				"clientType": "Web3.0",
				"loginType":  "Direct",
			},
			"id":      id,
			"session": 0,
		}, "")
	}
	r1, headers, err := emptyLogin(1)
	if err != nil {
		closeConn()
		return nil, err
	}
	cookie := rpc2SessionCookie(headers)

	var sess any
	if ok, _ := r1["result"].(bool); ok {
		if r2, h2, err2 := emptyLogin(1); err2 == nil {
			if res2, _ := r2["result"].(bool); !res2 {
				r1 = r2
				if c := rpc2SessionCookie(h2); c != "" {
					cookie = c
				}
			}
		}
		if ok, _ := r1["result"].(bool); ok {
			sess = r1["session"]
		}
	}

	if sess == nil {
		params, _ := r1["params"].(map[string]any)
		realm, _ := params["realm"].(string)
		random, _ := params["random"].(string)
		sessTmp := r1["session"]
		if realm == "" || random == "" {
			closeConn()
			return nil, fmt.Errorf("RPC2 login: no challenge received")
		}
		r2, headers2, err := conn.post("/RPC2_Login", map[string]any{
			"method": "global.login",
			"params": map[string]any{
				"userName":      login,
				"password":      p2p.StandardRPCHash(login, pass, realm, random),
				"clientType":    "Web3.0",
				"loginType":     "Direct",
				"authorityType": "Default",
			},
			"id":      2,
			"session": sessTmp,
		}, cookie)
		if err != nil {
			closeConn()
			return nil, err
		}
		if c := rpc2SessionCookie(headers2); c != "" {
			cookie = c
		}
		if ok, _ := r2["result"].(bool); !ok {
			closeConn()
			return nil, fmt.Errorf("RPC2 login rejected (%v)", r2["error"])
		}
		sess = r2["session"]
	}

	return &osdSession{
		get: func(name string, id int) (*cfgData, error) {
			t, err := rpc2GetTable(conn, sess, cookie, name, id)
			if err != nil {
				return nil, err
			}
			return &cfgData{nested: t}, nil
		},
		setBoth: func(ctOut, vwOut []any) error {
			return rpc2MulticallSet(conn, sess, cookie, ctOut, vwOut)
		},
		close: closeConn,
	}, nil
}

func newDHIPSession(tunnel *p2p.PTCPTunnel, port int, login, pass string) (*osdSession, error) {
	dhip, err := tunnel.NewDHIPClientOnPort(port)
	if err != nil {
		return nil, err
	}
	// Password login only
	if err := dhip.LoginNormal(login, pass); err != nil {
		dhip.Close()
		return nil, fmt.Errorf("dhip login: %w", err)
	}
	// get/set calls on the same dhip conn
	return &osdSession{
		get: func(name string, id int) (*cfgData, error) {
			t, err := dhipGetTable(dhip, name, id)
			if err != nil {
				return nil, err
			}
			return &cfgData{nested: t}, nil
		},
		setBoth: func(ctOut, vwOut []any) error {
			return dhipMulticallSet(dhip, ctOut, vwOut)
		},
		close: func() { dhip.Close() },
	}, nil
}

type cfgData struct {
	nested []any
}

type osdSession struct {
	get     func(name string, id int) (*cfgData, error)
	setBoth func(ctOut, vwOut []any) error
	close   func()
}

func checkMulticallResult(r map[string]any) error {
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("multicall: result false (%v)", r["error"])
	}
	params, _ := r["params"].([]any)
	if params == nil {
		return nil
	}
	for _, raw := range params {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		if ok, _ := m["result"].(bool); !ok {
			return fmt.Errorf("multicall call id=%v failed (%v)", m["id"], m["error"])
		}
	}
	return nil
}

func multicallSetCalls(sess any, ctOut, vwOut []any) []any {
	var calls []any
	if len(ctOut) > 0 {
		calls = append(calls, map[string]any{
			"method": "configManager.setConfig",
			"params": map[string]any{"name": "ChannelTitle", "table": ctOut, "options": []any{}},
			"id":     41, "session": sess,
		})
	}
	if len(vwOut) > 0 {
		calls = append(calls, map[string]any{
			"method": "configManager.setConfig",
			"params": map[string]any{"name": "VideoWidget", "table": vwOut, "options": []any{}},
			"id":     42, "session": sess,
		})
	}
	return calls
}

func rpc2MulticallSet(conn *rpc2ConnSession, sess any, cookie string, ctOut, vwOut []any) error {
	calls := multicallSetCalls(sess, ctOut, vwOut)
	if len(calls) == 0 {
		return fmt.Errorf("nothing to set")
	}
	conn.reqTimeout = 45 * time.Second
	r, _, err := conn.post("/RPC2", map[string]any{
		"method": "system.multicall", "params": calls, "id": 40, "session": sess,
	}, cookie)
	if err != nil {
		return err
	}
	return checkMulticallResult(r)
}

func dhipMulticallSet(dhip *p2p.DHIPClient, ctOut, vwOut []any) error {
	sess := dhip.Session()
	calls := multicallSetCalls(sess, ctOut, vwOut)
	if len(calls) == 0 {
		return fmt.Errorf("nothing to set")
	}
	r, err := dhip.Call("system.multicall", calls, 40, nil, nil)
	if err != nil {
		return err
	}
	return checkMulticallResult(r)
}

func verifyTitleState(label string, newSess func() (*osdSession, error), channel string, lines []string) (bool, bool) {
	ctOK, vwOK := channel == "", len(lines) == 0
	if ctOK && vwOK {
		return true, true
	}
	s, err := newSess()
	if err != nil {
		return channel == "", len(lines) == 0
	}
	defer s.close()
	if !ctOK {
		if d, err := s.get("ChannelTitle", 50); err == nil {
			for _, raw := range d.nested {
				if m, _ := raw.(map[string]any); m != nil {
					if n, _ := m["Name"].(string); n == channel {
						ctOK = true
						break
					}
				}
			}
		}
	}
	if !vwOK {
		found := map[string]bool{}
		if d, err := s.get("VideoWidget", 51); err == nil {
			for _, raw := range d.nested {
				m, _ := raw.(map[string]any)
				if m == nil {
					continue
				}
				ct, _ := m["CustomTitle"].([]any)
				for _, sraw := range ct {
					sm, _ := sraw.(map[string]any)
					if sm == nil {
						continue
					}
					if t, _ := sm["Text"].(string); t != "" {
						found[t] = true
					}
				}
			}
		}
		vwOK = found[pipeJoin(lines)]
	}
	return ctOK, vwOK
}

func applySingleShot(label string, newSess func() (*osdSession, error), channel string, lines []string) error {
	s, err := newSess()
	if err != nil {
		return fmt.Errorf("%s session: %w", label, err)
	}
	defer s.close()
	vwD, err := s.get("VideoWidget", 10)
	if err != nil {
		return fmt.Errorf("%s get VideoWidget: %w", label, err)
	}
	ctD, err := s.get("ChannelTitle", 11)
	if err != nil {
		return fmt.Errorf("%s get ChannelTitle: %w", label, err)
	}
	ctOut, vwOut := buildTitleSet(vwD.nested, ctD.nested, channel, lines)
	if len(ctOut) == 0 && len(vwOut) == 0 {
		return fmt.Errorf("%s: nothing to set", label)
	}
	time.Sleep(3 * time.Second)
	setErr := s.setBoth(ctOut, vwOut)
	if setErr == nil {
		return nil // device acknowledged per-call result:true
	}
	if !isConnBreakErr(setErr) {
		return fmt.Errorf("%s: %w", label, setErr)
	}
	ctOK, vwOK := verifyTitleState(label, newSess, channel, lines)
	if ctOK && vwOK {
		return nil
	}
	return fmt.Errorf("%s: %v (verified channel=%v video=%v)", label, setErr, ctOK, vwOK)
}

func isConnBreakErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sub := range []string{"timeout", "eof", "reset", "broken pipe", "disconnected", "connection refused"} {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func tryOSDPort(getTunnel func() *p2p.PTCPTunnel, port int, login, pass, channel string, lines []string) error {
	label := fmt.Sprintf("port %d", port)
	var newSess func() (*osdSession, error)
	if port == 80 {
		newSess = func() (*osdSession, error) { return newRPC2Session(getTunnel(), login, pass) }
	} else {
		newSess = func() (*osdSession, error) { return newDHIPSession(getTunnel(), port, login, pass) }
	}
	return applySingleShot(label, newSess, channel, lines)
}

func TryOSD(tunnel *p2p.PTCPTunnel, login, pass, channel string, custom []string, redial func() (*p2p.PTCPTunnel, func(), bool)) error {
	channel = normalizeOSDChannel(channel)
	lines := normalizeOSDLines(custom)
	if channel == "" && len(lines) == 0 {
		return fmt.Errorf("nothing to set (channel and custom are empty)")
	}

	cur := tunnel
	var cleanups []func()
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()
	healCount := 0
	heal := func() bool {
		if redial == nil || healCount >= 5 {
			return false
		}
		healCount++
		nt, cleanup, ok := redial()
		if !ok {
			return false
		}
		cur = nt
		cleanups = append(cleanups, cleanup)
		return true
	}
	getTunnel := func() *p2p.PTCPTunnel { return cur }

	runPort := func(port int) error {
		if err := tryOSDPort(getTunnel, port, login, pass, channel, lines); err == nil {
			return nil
		} else {
			if isConnBreakErr(err) && heal() {
				return tryOSDPort(getTunnel, port, login, pass, channel, lines)
			}
			return err
		}
	}

	if err := runPort(5000); err == nil {
		return nil
	}

	if err := runPort(80); err != nil {
		return fmt.Errorf("OSD skipped, 5000 and 80 failed: %w", err)
	}
	return nil
}
