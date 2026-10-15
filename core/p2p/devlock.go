package p2p

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	devLockMu    sync.Mutex
	devLockUntil = make(map[string]time.Time)
)

var lockSecondRe = regexp.MustCompile(`"remainLockSecond"\s*:\s*(\d+)`)

func NoteDeviceLocked(serial string, until time.Time) {
	if serial == "" {
		return
	}
	devLockMu.Lock()
	if cur, ok := devLockUntil[serial]; !ok || until.After(cur) {
		devLockUntil[serial] = until
	}
	devLockMu.Unlock()
}

func DeviceLockedUntil(serial string) time.Time {
	devLockMu.Lock()
	defer devLockMu.Unlock()
	if until, ok := devLockUntil[serial]; ok {
		if time.Now().Before(until) {
			return until
		}
		delete(devLockUntil, serial)
	}
	return time.Time{}
}

func ParseLockSeconds(resp map[string]any) (int, bool) {
	params, _ := resp["params"].(map[string]any)
	if params == nil {
		return 0, false
	}
	sec := lockInt(params["remainLockSecond"])
	if sec <= 0 {
		return 0, false
	}
	return sec, true
}

func lockInt(v any) int {
	switch n := v.(type) {
	case float64:
		if n > 0 {
			return int(n)
		}
	case int:
		if n > 0 {
			return n
		}
	case int64:
		if n > 0 {
			return int(n)
		}
	}
	return 0
}

func LockedSecondsText(text string) (int, bool) {
	m := lockSecondRe.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	sec := 0
	for _, c := range m[1] {
		sec = sec*10 + int(c-'0')
	}
	if sec <= 0 {
		return 0, false
	}
	return sec, true
}

func LockedWord(text string) bool {
	s := strings.ToLower(text)
	for _, w := range []string{"account locked", "user locked", "locked, try", "remainlock", "remainlogintimes", "lockout"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func noteLockFromResp(tunnel *PTCPTunnel, resp map[string]any) {
	sec, ok := ParseLockSeconds(resp)
	if !ok {
		return
	}
	serial := ""
	if tunnel != nil && tunnel.client != nil {
		serial = tunnel.client.serial
	}
	NoteDeviceLocked(serial, time.Now().Add(time.Duration(sec)*time.Second))
}
