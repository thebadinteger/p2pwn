package p2p

import (
	"strings"
	"sync/atomic"
	"time"
)

// cloud clock offset kept in memory only
var serverTimeOffset atomic.Int64

func nowAdjusted() time.Time {
	return time.Now().Add(-time.Duration(serverTimeOffset.Load()) * time.Second)
}

func updateServerTimeOffset(serverTime string) bool {
	s := strings.TrimSpace(serverTime)
	if s == "" {
		return false
	}

	t, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local)
	if err != nil {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err = time.Parse(layout, s); err == nil {
				break
			}
		}
		if err != nil {
			return false
		}
	}

	off := time.Since(t).Round(time.Second)
	secs := int64(off / time.Second)
	old := serverTimeOffset.Swap(secs)
	if delta := secs - old; delta > 20 || delta < -20 {
		LogDebugf("time", "server time offset changed from %ds to %ds", old, secs)
	}
	return true
}

func maybeUpdateTimeOffset(res *DHResponse) {
	if res == nil {
		return
	}
	for k, v := range res.Headers {
		if strings.EqualFold(k, "ServerTime") {
			updateServerTimeOffset(v)
			return
		}
	}
	for k, v := range res.XMLBody {
		tag := k
		if i := strings.LastIndexByte(tag, '/'); i >= 0 {
			tag = tag[i+1:]
		}
		if strings.EqualFold(tag, "ServerTime") {
			updateServerTimeOffset(v)
			return
		}
	}
	for _, line := range strings.Split(res.Body, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.EqualFold(strings.TrimSpace(k), "ServerTime") {
			updateServerTimeOffset(v)
			return
		}
	}
}
