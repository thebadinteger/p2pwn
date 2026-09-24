package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thebadinteger/p2pwn/core/p2p"
)

type DebugLogger struct {
	mu      sync.Mutex
	file    *os.File
	enabled bool
}

var globalDebug = &DebugLogger{}

func InitDebug(outDir string, enabled bool) error {
	globalDebug.mu.Lock()
	defer globalDebug.mu.Unlock()

	globalDebug.enabled = enabled
	if !enabled {
		p2p.SetDebugLogger(nil)
		return nil
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output dir for debug log: %w", err)
	}

	logPath := filepath.Join(outDir, "debug.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open debug log: %w", err)
	}

	globalDebug.file = f

	p2p.SetDebugLogger(func(tag string, msg string) {
		globalDebug.writeLog(tag, msg)
	})

	now := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(f, "[debug] %s\n", now)

	return nil
}

func (d *DebugLogger) writeLog(tag, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled || d.file == nil {
		return
	}

	ts := time.Now().Format("15:04:05.000")
	if tag != "" {
		fmt.Fprintf(d.file, "[%s] [%s] %s\n", ts, tag, msg)
	} else {
		fmt.Fprintf(d.file, "[%s] %s\n", ts, msg)
	}
}

func CloseDebug() {
	globalDebug.mu.Lock()
	defer globalDebug.mu.Unlock()

	if globalDebug.file != nil {
		now := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(globalDebug.file, "[finished] %s\n", now)
		globalDebug.file.Close()
		globalDebug.file = nil
	}
	globalDebug.enabled = false
	p2p.SetDebugLogger(nil)
}

func DebugLogf(tag, format string, args ...any) {
	if !globalDebug.enabled {
		return
	}
	globalDebug.writeLog(tag, fmt.Sprintf(format, args...))
}

// Debug
func LogScanStart(inputSource string, targetCount int64, threads int, configPath string, outDir string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("scanner", "scan started | input > %s | count > %d | threads > %d | config > %s | output > %s",
		inputSource, targetCount, threads, configPath, outDir)
}

func LogOnlineFound(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("online", "%s > is online", serial)
}

func LogHandshakeResult(serial string, dtype int, attempt int, err error) {
	if !globalDebug.enabled {
		return
	}
	if err == nil {
		DebugLogf("hs", "%s > ok (type=%d, attempt=%d)", serial, dtype, attempt+1)
	} else {
		DebugLogf("hs", "%s > fail (type=%d, attempt=%d): %v", serial, dtype, attempt+1, err)
	}
}

func LogType1ChannelAuthRequired(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("type1", "%s > p2p-channel requires authentication (code 403)", serial)
}

func LogType1TimeoutAssume(serial string, err error) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("type1", "%s > handshake failed (%v), switching to Type 1", serial, err)
}

func LogType1Start(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("type1", "%s > trying Type 0 tunnel probe and Type 1 credentials", serial)
}

func LogType1TunnelSuccess(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("type1", "%s > type 0 tunnel established for type 1 device", serial)
}

func LogType1Skipped(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("type1", "%s > type 1 protocol is disabled in config", serial)
}

func LogType1Brute(serial string, login string, pass string, attempt int, err error) {
	if !globalDebug.enabled {
		return
	}
	if err == nil {
		DebugLogf("type1", "%s > brute ok (user=%s, pass=%s, attempt=%d)", serial, login, pass, attempt)
	} else {
		DebugLogf("type1", "%s > brute fail (user=%s, pass=%s, attempt=%d): %v", serial, login, pass, attempt, err)
	}
}

func LogExploitPwned(serial string, method string, login, pass string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("exploit", "%s > pwned via %s (user=%s, pass=%s)", serial, method, login, pass)
}

func LogExploitStart(serial string, ip string) {
	if !globalDebug.enabled {
		return
	}
	if ip != "" {
		DebugLogf("exploit", "%s > starting exploit pipeline (IP=%s)", serial, ip)
	} else {
		DebugLogf("exploit", "%s > starting exploit pipeline", serial)
	}
}

func LogExploitStageFailed(serial string, stage string, err error) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("exploit", "%s > stage %s failed: %v", serial, stage, err)
}

func LogExploitUnpwned(serial string) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("exploit", "%s > unpwned (all methods failed, device is safe)", serial)
}

func LogTunnelEstablishResult(serial string, attempt int, direct bool, err error) {
	if !globalDebug.enabled {
		return
	}
	mode := "relay"
	if direct {
		mode = "direct"
	}
	if err == nil {
		DebugLogf("tunnel", "%s > established %s tunnel (attempt %d)", serial, mode, attempt+1)
	} else {
		DebugLogf("tunnel", "%s > failed %s tunnel (attempt %d): %v", serial, mode, attempt+1, err)
	}
}

func LogOSDResult(serial string, port int, success bool, err error) {
	if !globalDebug.enabled {
		return
	}
	if success {
		DebugLogf("osd", "%s > applied OSD on port %d", serial, port)
	} else {
		DebugLogf("osd", "%s > osd port %d failed: %v", serial, port, err)
	}
}

func LogSnapshotResult(serial string, filename string, success bool, err error) {
	if !globalDebug.enabled {
		return
	}
	if success {
		DebugLogf("snapshot", "%s > snapshot saved (%s)", serial, filename)
	} else {
		if err != nil {
			DebugLogf("snapshot", "%s > snapshot failed: %v", serial, err)
		} else {
			DebugLogf("snapshot", "%s > snapshot failed", serial)
		}
	}
}

func LogBruteCheckResult(serial string, proto string, user string, pass string, success bool, err error) {
	if !globalDebug.enabled {
		return
	}
	if success {
		DebugLogf("brute", "%s > %s auth ok (user=%s, pass=%s)", serial, proto, user, pass)
	} else {
		if err != nil {
			DebugLogf("brute", "%s > %s auth fail (user=%s, pass=%s): %v", serial, proto, user, pass, err)
		} else {
			DebugLogf("brute", "%s > %s auth fail (user=%s, pass=%s)", serial, proto, user, pass)
		}
	}
}

func LogScanFinish(completed int64, pwned int64, online int64, waste int64, total int64) {
	if !globalDebug.enabled {
		return
	}
	DebugLogf("scanner", "scan finished | total > %d | completed > %d | pwned > %d | online > %d | waste > %d",
		total, completed, pwned, online, waste)
}
