package p2p

import (
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxTrustedSkew  = 10 * time.Minute
	maxAbsoluteSkew = 24 * time.Hour
)

// cloud clock offset kept in memory only
var serverTimeOffset atomic.Int64

func nowAdjusted() time.Time {
	secs := serverTimeOffset.Load()
	if secs > int64(maxAbsoluteSkew/time.Second) || secs < -int64(maxAbsoluteSkew/time.Second) {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(secs) * time.Second)
}

func parseServerTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, false
		}
	}
	return time.Time{}, false
}

func updateServerTimeOffset(serverTime string) bool {
	s := strings.TrimSpace(serverTime)
	if s == "" {
		return false
	}

	t, explicit := parseServerTime(s)
	if t.IsZero() {
		return false
	}

	off := time.Since(t)
	if off > maxAbsoluteSkew || off < -maxAbsoluteSkew {
		LogDebugf("time", "server time %q too far from local clock, keeping current offset", s)
		return false
	}
	if !explicit && (off > maxTrustedSkew || off < -maxTrustedSkew) {
		LogDebugf("time", "server time %q has no zone and %s drift, keeping current offset", s, off.Round(time.Second))
		return false
	}

	secs := int64(off.Round(time.Second) / time.Second)
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
