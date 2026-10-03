package p2p

// channel probe pipeline for online checks

import (
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pipeWindowStart    = 8
	pipeWindowMin      = 8
	pipeWindowMax      = 128
	pipeWindowGrow     = 8
	pipeWindowShrink   = 16
	pipeAckTimeout     = 15 * time.Second
	pipeAckGrace       = 15 * time.Second
	pipeChannelRetries = 2
	pipeMaxRPS         = 3000
	pipeBurst          = 64
	pipeStartRPS       = 500
	pipeFloorRPS       = 100
	pipeTick           = 1 * time.Second
	pipeRTTRing        = 512
	pipeWarmupWait     = 2 * time.Second
)

type PipeVerdict struct {
	Serial string
	Alive  bool
}

type pipeLimiter struct {
	interval time.Duration
	burst    time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newPipeLimiter(rps, burst int) *pipeLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	inv := time.Second / time.Duration(rps)
	return &pipeLimiter{
		interval: inv,
		burst:    time.Duration(burst) * inv,
		next:     time.Now(),
	}
}

func (rl *pipeLimiter) wait(done <-chan struct{}) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.Before(now) {
		rl.next = now
	}
	reserve := rl.next
	rl.next = rl.next.Add(rl.interval)
	rl.mu.Unlock()

	delay := reserve.Sub(now)
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

func (rl *pipeLimiter) setRPS(rps int) {
	if rl == nil || rps <= 0 {
		return
	}
	rl.mu.Lock()
	rl.interval = time.Second / time.Duration(rps)
	rl.burst = time.Duration(pipeBurst) * rl.interval
	rl.mu.Unlock()
}

var (
	pipeGovPPS        int64 = pipeStartRPS
	pipeGovSlow       int64 = 1
	pipeGovOK         int64
	pipeGovTO         int64
	pipeGovRTT        [pipeRTTRing]int64
	pipeGovRTTIdx     int64
	pipeGovRTTBase    int64
	pipeGovOnce       sync.Once
	pipeSharedLimiter *pipeLimiter
)

func pipeLimiterShared() *pipeLimiter {
	pipeGovOnce.Do(func() {
		pipeSharedLimiter = newPipeLimiter(pipeStartRPS, pipeBurst)
		go pipeGovernorLoop()
	})
	return pipeSharedLimiter
}

func pipeRecordOK(rtt time.Duration) {
	atomic.AddInt64(&pipeGovOK, 1)
	if rtt > 0 {
		i := atomic.AddInt64(&pipeGovRTTIdx, 1) % pipeRTTRing
		atomic.StoreInt64(&pipeGovRTT[i], rtt.Microseconds())
	}
}

func pipeRecordTO() { atomic.AddInt64(&pipeGovTO, 1) }

func pipeMedianRTT() int64 {
	vals := make([]int64, 0, pipeRTTRing)
	for i := 0; i < pipeRTTRing; i++ {
		if v := atomic.LoadInt64(&pipeGovRTT[i]); v > 0 {
			vals = append(vals, v*1000)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(a, b int) bool { return vals[a] < vals[b] })
	return vals[len(vals)/2]
}

func pipeGovernorLoop() {
	t := time.NewTicker(pipeTick)
	defer t.Stop()
	for range t.C {
		ok := atomic.SwapInt64(&pipeGovOK, 0)
		to := atomic.SwapInt64(&pipeGovTO, 0)
		total := ok + to
		if total == 0 {
			continue
		}
		lossPct := float64(to) * 100 / float64(total)
		pps := int(atomic.LoadInt64(&pipeGovPPS))
		newPPS := pps

		bloat := false
		if med := pipeMedianRTT(); med > 0 {
			base := atomic.LoadInt64(&pipeGovRTTBase)
			if base > 0 && med > base*5/2 {
				bloat = true
			}
			if lossPct < 3 {
				if base == 0 {
					atomic.StoreInt64(&pipeGovRTTBase, med)
				} else {
					atomic.StoreInt64(&pipeGovRTTBase, base*9/10+med/10)
				}
			}
		}

		switch {
		case lossPct > 15:
			newPPS = pps / 2
			atomic.StoreInt64(&pipeGovSlow, 0)
		case bloat:
			newPPS = pps * 7 / 10
			atomic.StoreInt64(&pipeGovSlow, 0)
		case lossPct < 3 && atomic.LoadInt64(&pipeGovSlow) == 1:
			newPPS = pps * 2
		case lossPct < 15:
			newPPS = pps + pps/20
		}
		if newPPS < pipeFloorRPS {
			newPPS = pipeFloorRPS
		}
		if newPPS > pipeMaxRPS {
			newPPS = pipeMaxRPS
		}
		if newPPS != pps {
			atomic.StoreInt64(&pipeGovPPS, int64(newPPS))
			pipeSharedLimiter.setRPS(newPPS)
		}
	}
}

type pipeInflight struct {
	serial   string
	deadline time.Time
	extended bool
	retries  int
	sentAt   time.Time
}

type pipeGrave struct {
	serial   string
	retries  int
	deadline time.Time
}

type checkPipeline struct {
	conn          *net.UDPConn
	lport         int
	timeout       time.Duration
	grace         time.Duration
	window        int
	sent          int64
	resolved      int64
	expired       int64
	inflight      map[uint32]*pipeInflight
	graveyard     map[uint32]*pipeGrave
	buf           []byte
	limiter       *pipeLimiter
	done          <-chan struct{}
	verdicts      chan<- PipeVerdict
	lastReconnect time.Time
}

func pipeChannelBody(lport int, aid []byte) string {
	parts := make([]string, 0, len(aid))
	for _, b := range aid {
		parts = append(parts, fmt.Sprintf("%x", b))
	}
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version>",
		strings.Join(parts, " "), lport)
}

func pipeTagValue(s, tag string) string {
	open, close := "<"+tag+">", "</"+tag+">"
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(s[:j])
}

func pipeAlive(resp *DHResponse) bool {
	if resp.Code < 200 || resp.Code >= 400 {
		return false
	}
	return pipeTagValue(resp.Body, "LocalAddr") != ""
}

func pipeRespCSeq(resp *DHResponse) (uint32, bool) {
	h, ok := resp.Headers["CSeq"]
	if !ok || h == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(h), 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

// report a socket-level failure
func isUDPHardError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "broken pipe")
}

func (p *checkPipeline) reconnect() {
	if time.Since(p.lastReconnect) < time.Second {
		return
	}
	p.lastReconnect = time.Now()
	raddr, _ := p.conn.RemoteAddr().(*net.UDPAddr)
	p.conn.Close()
	if raddr == nil {
		return
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return
	}
	conn.SetWriteBuffer(64 * 1024)
	conn.SetReadBuffer(256 * 1024)
	p.conn = conn
	p.lport = conn.LocalAddr().(*net.UDPAddr).Port
}

func (p *checkPipeline) waitRate() bool {
	if p.limiter == nil {
		return true
	}
	return p.limiter.wait(p.done)
}

func (p *checkPipeline) cancelled() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *checkPipeline) send(serial string) bool {
	if !p.waitRate() {
		return false
	}
	cseq := SmartPSSProfile.nextCSeq()
	aid := make([]byte, 8)
	rand.Read(aid)
	body := pipeChannelBody(p.lport, aid)
	req := SmartPSSProfile.buildRequest(SmartPSSProfile.verbFor(body), "/device/"+serial+"/p2p-channel", body, true, cseq)
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	if _, err := p.conn.Write(req); err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		return false
	}
	p.inflight[cseq] = &pipeInflight{serial: serial, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
	p.sent++
	return true
}

func (p *checkPipeline) emit(serial string, alive bool) {
	select {
	case p.verdicts <- PipeVerdict{Serial: serial, Alive: alive}:
	case <-p.done:
	}
}

func (p *checkPipeline) readResp(dl time.Time) (*DHResponse, bool) {
	p.conn.SetReadDeadline(dl)
	n, err := p.conn.Read(p.buf)
	if err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		return nil, false
	}
	resp, perr := parseDHResponse(p.buf[:n])
	if perr != nil {
		return nil, false
	}
	return resp, true
}

func (p *checkPipeline) minDeadline() time.Time {
	var m time.Time
	for _, ir := range p.inflight {
		if m.IsZero() || ir.deadline.Before(m) {
			m = ir.deadline
		}
	}
	for _, g := range p.graveyard {
		if m.IsZero() || g.deadline.Before(m) {
			m = g.deadline
		}
	}
	return m
}

func (p *checkPipeline) resolve(resp *DHResponse) {
	cseq, ok := pipeRespCSeq(resp)
	if !ok {
		return
	}
	if resp.Code < 200 {
		if ir, found := p.inflight[cseq]; found && !ir.extended {
			ir.extended = true
			ir.deadline = time.Now().Add(p.timeout)
		}
		return
	}
	if ir, found := p.inflight[cseq]; found {
		delete(p.inflight, cseq)
		p.resolved++
		pipeRecordOK(time.Since(ir.sentAt))
		p.emit(ir.serial, pipeAlive(resp))
		return
	}
	if g, found := p.graveyard[cseq]; found {
		delete(p.graveyard, cseq)
		p.resolved++
		p.emit(g.serial, pipeAlive(resp))
		return
	}
}

func (p *checkPipeline) expire() {
	now := time.Now()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.expired++
			pipeRecordTO()
			p.graveyard[c] = &pipeGrave{serial: ir.serial, retries: ir.retries, deadline: now.Add(p.grace)}
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			delete(p.graveyard, c)
			if g.retries >= pipeChannelRetries {
				p.emit(g.serial, false)
				continue
			}
			p.sendRetry(g)
		}
	}
}

func (p *checkPipeline) sendRetry(g *pipeGrave) {
	if !p.waitRate() {
		p.emit(g.serial, false)
		return
	}
	cseq := SmartPSSProfile.nextCSeq()
	aid := make([]byte, 8)
	rand.Read(aid)
	body := pipeChannelBody(p.lport, aid)
	req := SmartPSSProfile.buildRequest(SmartPSSProfile.verbFor(body), "/device/"+g.serial+"/p2p-channel", body, true, cseq)
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	if _, err := p.conn.Write(req); err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		p.emit(g.serial, false)
		return
	}
	p.inflight[cseq] = &pipeInflight{serial: g.serial, deadline: time.Now().Add(p.timeout), retries: g.retries + 1, sentAt: time.Now()}
	p.sent++
}

func (p *checkPipeline) govern() {
	total := p.resolved + p.expired
	if total == 0 {
		return
	}
	share := float64(p.expired) / float64(total)
	switch {
	case share < 0.02:
		p.window += pipeWindowGrow
		if p.window > pipeWindowMax {
			p.window = pipeWindowMax
		}
	case share > 0.10:
		p.window -= pipeWindowShrink
		if p.window < pipeWindowMin {
			p.window = pipeWindowMin
		}
	}
	p.sent = 0
	p.resolved, p.expired = 0, 0
}

func (p *checkPipeline) pump() {
	dl := p.minDeadline()
	wait := time.Until(dl)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	if resp, got := p.readResp(time.Now().Add(wait)); got {
		p.resolve(resp)
	}
	p.expire()
}

func (p *checkPipeline) run(jobs <-chan string) {
	for {
		if p.cancelled() {
			return
		}
		for len(p.inflight) < p.window {
			select {
			case <-p.done:
				return
			case s, ok := <-jobs:
				if !ok {
					goto drain
				}
				if !p.send(s) {
					if p.cancelled() {
						return
					}
					p.emit(s, false)
				}
			default:
				goto readPhase
			}
		}
	readPhase:
		if len(p.inflight) == 0 && len(p.graveyard) == 0 {
			select {
			case <-p.done:
				return
			case s, ok := <-jobs:
				if !ok {
					return
				}
				if !p.send(s) {
					if p.cancelled() {
						return
					}
					p.emit(s, false)
				}
			}
			continue
		}
		p.pump()
		if p.resolved+p.expired >= int64(p.window) {
			p.govern()
		}
	}
drain:
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && !p.cancelled() {
		p.pump()
		if p.resolved+p.expired >= int64(p.window) {
			p.govern()
		}
	}
}

type CheckPipe struct {
	jobs     chan string
	verdicts chan PipeVerdict
	wg       sync.WaitGroup
	pipes    []*checkPipeline
	done     <-chan struct{}
}

func NewCheckPipe(workers int, done <-chan struct{}) (*CheckPipe, error) {
	if workers < 1 {
		workers = 1
	}
	limiter := pipeLimiterShared()
	var conns []*net.UDPConn
	for i := 0; i < workers; i++ {
		raddr, err := resolveCached(SmartPSSProfile.MainServer)
		if err != nil || raddr == nil {
			continue
		}
		conn, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			continue
		}
		conn.SetWriteBuffer(64 * 1024)
		conn.SetReadBuffer(256 * 1024)
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil, fmt.Errorf("check pipe: no udp sockets")
	}
	c := &CheckPipe{
		jobs:     make(chan string, len(conns)*10),
		verdicts: make(chan PipeVerdict, len(conns)*10),
		done:     done,
	}
	for _, conn := range conns {
		w := &checkPipeline{
			conn:      conn,
			lport:     conn.LocalAddr().(*net.UDPAddr).Port,
			timeout:   pipeAckTimeout,
			grace:     pipeAckGrace,
			window:    pipeWindowStart,
			inflight:  make(map[uint32]*pipeInflight, pipeWindowStart),
			graveyard: make(map[uint32]*pipeGrave, pipeWindowStart),
			buf:       make([]byte, 65536),
			limiter:   limiter,
			done:      done,
			verdicts:  c.verdicts,
		}
		c.pipes = append(c.pipes, w)
		c.wg.Add(1)
		go func(w *checkPipeline) {
			defer c.wg.Done()
			w.warmup()
			w.run(c.jobs)
		}(w)
	}
	return c, nil
}

func (w *checkPipeline) warmup() {
	cseq := SmartPSSProfile.nextCSeq()
	req := SmartPSSProfile.buildRequest("DHGET", "/probe/p2psrv", "", true, cseq)
	w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
	if _, err := w.conn.Write(req); err != nil {
		return
	}
	dl := time.Now().Add(pipeWarmupWait)
	for {
		w.conn.SetReadDeadline(dl)
		n, err := w.conn.Read(w.buf)
		if err != nil {
			return
		}
		if resp, perr := parseDHResponse(w.buf[:n]); perr == nil {
			if c, ok := pipeRespCSeq(resp); ok && c == cseq {
				return
			}
		}
	}
}

func (c *CheckPipe) Jobs() chan<- string { return c.jobs }

func (c *CheckPipe) Verdicts() <-chan PipeVerdict { return c.verdicts }

func (c *CheckPipe) Close() {
	close(c.jobs)
	c.wg.Wait()
	close(c.verdicts)
	for _, p := range c.pipes {
		p.conn.Close()
	}
}
