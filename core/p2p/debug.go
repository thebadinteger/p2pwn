package p2p

import (
	"fmt"
	"sync/atomic"
)

var p2pDebugLogger atomic.Value

func SetDebugLogger(fn func(tag, msg string)) {
	if fn == nil {
		p2pDebugLogger.Store((func(tag, msg string))(nil))
	} else {
		p2pDebugLogger.Store(fn)
	}
}

func LogDebugf(tag string, format string, args ...any) {
	if v := p2pDebugLogger.Load(); v != nil {
		if fn, ok := v.(func(tag, msg string)); ok && fn != nil {
			fn(tag, fmt.Sprintf(format, args...))
		}
	}
}
