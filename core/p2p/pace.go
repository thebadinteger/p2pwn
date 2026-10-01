package p2p

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	paceStartRPS = 500
	paceFloorRPS = 100
	paceMaxRPS   = 3000
	paceTick     = 1000 * time.Millisecond
	paceBurst    = 64
	paceRTTRing  = 512
)

type checkPacer struct {
	mu       sync.Mutex
	interval time.Duration
	burst    time.Duration
	next     time.Time
	rps      int64

	okCount int64
	toCount int64

	attOk   [3]int64
	writeEr int64
	drained int64

	rtt     [paceRTTRing]int64
	rttIdx  int64
	rttBase int64
	slow    int64

	startOnce sync.Once
}

func newCheckPacer() *checkPacer {
	p := &checkPacer{rps: paceStartRPS, slow: 1}
	p.setRPS(paceStartRPS)
	return p
}

func (p *checkPacer) ensureStarted() {
	p.startOnce.Do(func() { go p.loop() })
}

func (p *checkPacer) setRPS(rps int) {
	if rps <= 0 {
		return
	}
	p.mu.Lock()
	p.interval = time.Second / time.Duration(rps)
	p.burst = time.Duration(paceBurst) * p.interval
	p.mu.Unlock()
	atomic.StoreInt64(&p.rps, int64(rps))
}

func (p *checkPacer) acquire() {
	p.ensureStarted()
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now.Add(-p.burst)) {
		p.next = now.Add(-p.burst)
	}
	wait := p.next.Sub(now)
	if wait < 0 {
		wait = 0
	}
	p.next = p.next.Add(p.interval)
	p.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

func (p *checkPacer) report(ok bool, rtt time.Duration) {
	if ok {
		atomic.AddInt64(&p.okCount, 1)
		if rtt > 0 {
			i := atomic.AddInt64(&p.rttIdx, 1) % paceRTTRing
			atomic.StoreInt64(&p.rtt[i], rtt.Microseconds())
		}
	} else {
		atomic.AddInt64(&p.toCount, 1)
	}
}

func (p *checkPacer) rttStats() (med, p95, mx int64) {
	vals := make([]int64, 0, paceRTTRing)
	for i := 0; i < paceRTTRing; i++ {
		if v := atomic.LoadInt64(&p.rtt[i]); v > 0 {
			vals = append(vals, v*1000)
		}
	}
	if len(vals) == 0 {
		return 0, 0, 0
	}
	sort.Slice(vals, func(a, b int) bool { return vals[a] < vals[b] })
	mx = vals[len(vals)-1]
	p95 = vals[len(vals)*95/100]
	return vals[len(vals)/2], p95, mx
}

func (p *checkPacer) loop() {
	t := time.NewTicker(paceTick)
	defer t.Stop()
	for range t.C {
		ok := atomic.SwapInt64(&p.okCount, 0)
		to := atomic.SwapInt64(&p.toCount, 0)
		total := ok + to
		if total == 0 {
			continue
		}
		lossPct := float64(to) * 100 / float64(total)
		pps := int(atomic.LoadInt64(&p.rps))
		newPPS := pps

		bloat := false
		med, p95, mx := p.rttStats()
		if med > 0 {
			base := atomic.LoadInt64(&p.rttBase)
			if base > 0 && med > base*5/2 {
				bloat = true
			}
			if lossPct < 3 {
				if base == 0 {
					atomic.StoreInt64(&p.rttBase, med)
				} else {
					atomic.StoreInt64(&p.rttBase, base*9/10+med/10)
				}
			}
		}

		switch {
		case lossPct > 15:
			newPPS = pps / 2
			atomic.StoreInt64(&p.slow, 0)
		case bloat:
			newPPS = pps * 7 / 10
			atomic.StoreInt64(&p.slow, 0)
		case lossPct < 3 && atomic.LoadInt64(&p.slow) == 1:
			newPPS = pps * 2
		case lossPct < 15:
			newPPS = pps + pps/20
		}
		if newPPS < paceFloorRPS {
			newPPS = paceFloorRPS
		}
		if newPPS > paceMaxRPS {
			newPPS = paceMaxRPS
		}
		if newPPS != pps {
			p.setRPS(newPPS)
		}
		slowAddr, slowTo, slowOk, slowSkip := "", int64(0), int64(0), int64(0)
		paceRelays.Range(func(key, value any) bool {
			s := value.(*paceRelayStats)
			to := atomic.LoadInt64(&s.to)
			if to >= 5 && to > slowTo {
				slowTo = to
				slowAddr, _ = key.(string)
				slowOk = atomic.LoadInt64(&s.ok)
				slowSkip = atomic.LoadInt64(&s.skip)
			}
			return true
		})
		slowInfo := ""
		if slowAddr != "" {
			slowInfo = fmt.Sprintf(" slow=%s to=%d ok=%d skip=%d", slowAddr, slowTo, slowOk, slowSkip)
		}
		a1 := atomic.SwapInt64(&p.attOk[0], 0)
		a2 := atomic.SwapInt64(&p.attOk[1], 0)
		a3 := atomic.SwapInt64(&p.attOk[2], 0)
		werr := atomic.SwapInt64(&p.writeEr, 0)
		dr := atomic.SwapInt64(&p.drained, 0)
		act := atomic.LoadInt64(&paceActive)
		LogDebugf("pace", "rps=%d loss=%.1f%% ok=%d to=%d a1=%d a2=%d a3=%d werr=%d drain=%d active=%d rtt=%d/%d/%dus bloat=%v%s",
			newPPS, lossPct, ok, to, a1, a2, a3, werr, dr, act, med/1000, p95/1000, mx/1000, bloat, slowInfo)
	}
}

var globalCheckPacer = newCheckPacer()

func PaceAcquire() { globalCheckPacer.acquire() }

func PaceReport(ok bool, rtt time.Duration) { globalCheckPacer.report(ok, rtt) }

var paceActive int64

type paceRelayStats struct {
	ok   int64
	to   int64
	skip int64
}

var paceRelays sync.Map

func paceRelay(addr *net.UDPAddr) *paceRelayStats {
	key := addr.String()
	if v, ok := paceRelays.Load(key); ok {
		return v.(*paceRelayStats)
	}
	actual, _ := paceRelays.LoadOrStore(key, &paceRelayStats{})
	return actual.(*paceRelayStats)
}
