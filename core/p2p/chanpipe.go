package p2p

// channel probe pipeline for online checks

import (
	"crypto/rand"
	"encoding/binary"
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
	pipeWindowStart    = 32
	pipeWindowMin      = 8
	pipeWindowMax      = 128
	pipeWindowGrow     = 8
	pipeWindowShrink   = 16
	pipeAckTimeout     = 15 * time.Second
	pipeAckGrace       = 15 * time.Second
	pipeChannelRetries = 2
	pipeMaxRPS         = 3000
	pipeBurst          = 64
	pipeStartRPS       = 150
	pipeFloorRPS       = 50
	pipeTick           = 2500 * time.Millisecond
	pipeSlowStartPct   = 3
	pipeCaPct          = 15
	pipeBackoffPct     = 15
	pipeRTTRing        = 512
	pipeWarmupWait     = 2 * time.Second
	pipeTeardownAlive  = true
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

// nonblocking slot claim for the hot loop
func (rl *pipeLimiter) tryReserve() bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.After(now) {
		return false
	}
	rl.next = rl.next.Add(rl.interval)
	return true
}

// blocking slot claim for the idle path
func (rl *pipeLimiter) blockRate(done <-chan struct{}) bool {
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

func (rl *pipeLimiter) nextDelay() time.Duration {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	d := time.Until(rl.next)
	if d < 0 {
		d = 0
	}
	return d
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
	pipeGovHealthy    int64
	pipeGovOK         int64
	pipeGovTO         int64
	pipeGovErr        int64
	pipeGovRTT        [pipeRTTRing]int64
	pipeGovRTTIdx     int64
	pipeGovRTTBase    int64
	pipeGovOnce       sync.Once
	pipeSharedLimiter *pipeLimiter
)

func pipeResetGov() {
	atomic.StoreInt64(&pipeGovPPS, pipeStartRPS)
	atomic.StoreInt64(&pipeGovSlow, 1)
	atomic.StoreInt64(&pipeGovHealthy, 0)
	atomic.StoreInt64(&pipeGovOK, 0)
	atomic.StoreInt64(&pipeGovTO, 0)
	atomic.StoreInt64(&pipeGovErr, 0)
	atomic.StoreInt64(&pipeGovRTTIdx, 0)
	atomic.StoreInt64(&pipeGovRTTBase, 0)
	for i := range pipeGovRTT {
		atomic.StoreInt64(&pipeGovRTT[i], 0)
	}
}

func pipeLimiterShared() *pipeLimiter {
	pipeGovOnce.Do(func() {
		pipeSharedLimiter = newPipeLimiter(pipeStartRPS, pipeBurst)
		go pipeGovernorLoop()
	})
	pipeResetGov()
	pipeSharedLimiter.setRPS(pipeStartRPS)
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

func pipeRecordErr() { atomic.AddInt64(&pipeGovErr, 1) }

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

// slow start then aimd with rtt bloat guard
func pipeGovernorLoop() {
	t := time.NewTicker(pipeTick)
	defer t.Stop()
	for range t.C {
		ok := atomic.SwapInt64(&pipeGovOK, 0)
		to := atomic.SwapInt64(&pipeGovTO, 0)
		er := atomic.SwapInt64(&pipeGovErr, 0)
		total := ok + to + er
		if total == 0 {
			continue
		}
		lossPct := float64(to+er) * 100 / float64(total)

		pps := atomic.LoadInt64(&pipeGovPPS)
		newPPS := pps
		hard := false

		bloat := false
		if med := pipeMedianRTT(); med > 0 {
			base := atomic.LoadInt64(&pipeGovRTTBase)
			if base > 0 && med > base*5/2 {
				bloat = true
			}
			if lossPct < float64(pipeSlowStartPct) {
				if base == 0 {
					atomic.StoreInt64(&pipeGovRTTBase, med)
				} else {
					atomic.StoreInt64(&pipeGovRTTBase, base*9/10+med/10)
				}
			}
		}

		switch {
		case (er >= 3 && er*100 >= total*5) || lossPct > float64(pipeBackoffPct):
			newPPS = pps / 2
			atomic.StoreInt64(&pipeGovSlow, 0)
			hard = true
		case bloat:
			newPPS = pps * 7 / 10
			atomic.StoreInt64(&pipeGovSlow, 0)
			hard = true
		case lossPct < float64(pipeSlowStartPct) && atomic.LoadInt64(&pipeGovSlow) == 1:
			newPPS = pps * 3 / 2
		case lossPct < float64(pipeCaPct):
			newPPS = pps + pps/20
		}
		if !hard && lossPct < float64(pipeSlowStartPct) {
			if atomic.AddInt64(&pipeGovHealthy, 1) >= 8 {
				atomic.StoreInt64(&pipeGovSlow, 1)
			}
		} else {
			atomic.StoreInt64(&pipeGovHealthy, 0)
		}
		if newPPS < pipeFloorRPS {
			newPPS = pipeFloorRPS
		}
		if newPPS > pipeMaxRPS {
			newPPS = pipeMaxRPS
		}
		if newPPS != pps {
			atomic.StoreInt64(&pipeGovPPS, newPPS)
			pipeSharedLimiter.setRPS(int(newPPS))
		}
	}
}

type pipeInflight struct {
	serial   string
	aid      []byte
	deadline time.Time
	extended bool
	retries  int
	sentAt   time.Time
}

type pipeGrave struct {
	serial   string
	aid      []byte
	retries  int
	deadline time.Time
}

type checkPipeline struct {
	conn          *net.UDPConn
	lport         int
	timeout       time.Duration
	grace         time.Duration
	window        int
	resolvedCycle int64
	expiredCycle  int64
	expiredEMA    float64
	emaSet        bool
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
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version></body>",
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
	if h, ok := resp.Headers["CSeq"]; ok {
		return pipeParseCSeq(h)
	}
	for k, h := range resp.Headers {
		if strings.EqualFold(k, "CSeq") {
			return pipeParseCSeq(h)
		}
	}
	return 0, false
}

func pipeParseCSeq(h string) (uint32, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(h), 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

// socket level failure as opposed to a normal timeout
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

// a connected udp socket poisoned by icmp unreachable errors on every
// read forever redial gives the worker a clean one
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

func (p *checkPipeline) tryRate() bool {
	if p.limiter == nil {
		return true
	}
	return p.limiter.tryReserve()
}

func (p *checkPipeline) blockRate() bool {
	if p.limiter == nil {
		return true
	}
	return p.limiter.blockRate(p.done)
}

func (p *checkPipeline) nextRateDelay() time.Duration {
	if p.limiter == nil {
		return 0
	}
	return p.limiter.nextDelay()
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
		pipeRecordErr()
		return false
	}
	p.inflight[cseq] = &pipeInflight{serial: serial, aid: aid, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
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
		p.resolvedCycle++
		pipeRecordOK(time.Since(ir.sentAt))
		alive := pipeAlive(resp)
		p.emit(ir.serial, alive)
		if alive {
			p.teardown(ir.aid, resp)
		}
		return
	}
	if g, found := p.graveyard[cseq]; found {
		delete(p.graveyard, cseq)
		p.resolvedCycle++
		alive := pipeAlive(resp)
		p.emit(g.serial, alive)
		if alive {
			p.teardown(g.aid, resp)
		}
		return
	}
}

// release the cloud channel after an alive verdict
func (p *checkPipeline) teardown(aid []byte, resp *DHResponse) {
	if !pipeTeardownAlive {
		return
	}
	inv := make([]byte, 8)
	for i, b := range aid {
		inv[i] = ^b
	}
	build := func(eaddr []byte) []byte {
		out := make([]byte, 0, 40)
		out = append(out, 0xFF, 0xFE, 0xFF, 0xE7)
		c1 := make([]byte, 8)
		rand.Read(c1)
		c2 := make([]byte, 8)
		rand.Read(c2)
		out = append(out, c1[:4]...)
		out = append(out, c2[:]...)
		out = append(out, c1[4:]...)
		out = append(out, 0x7F, 0xD5, 0xFF, 0xF7)
		out = append(out, inv...)
		out = append(out, 0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE)
		out = append(out, eaddr...)
		return out
	}
	for _, addrStr := range []string{
		pipeTagValue(resp.Body, "LocalAddr"),
		pipeTagValue(resp.Body, "PubAddr"),
	} {
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			continue
		}
		eaddr := make([]byte, 6)
		binary.BigEndian.PutUint16(eaddr[0:2], uint16(port))
		copy(eaddr[2:], ip)
		for i := range eaddr {
			eaddr[i] = ^eaddr[i]
		}
		init := build(eaddr)
		p.conn.WriteTo(init, &net.UDPAddr{IP: ip, Port: port})
		p.conn.Write(init)
	}
}

func (p *checkPipeline) expire() {
	now := time.Now()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.expiredCycle++
			pipeRecordTO()
			p.graveyard[c] = &pipeGrave{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: now.Add(p.grace)}
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			if g.retries >= pipeChannelRetries {
				delete(p.graveyard, c)
				p.emit(g.serial, false)
				continue
			}
			if !p.tryRate() {
				g.deadline = now.Add(p.nextRateDelay() + time.Millisecond)
				continue
			}
			delete(p.graveyard, c)
			p.sendRetry(g)
		}
	}
}

func (p *checkPipeline) sendRetry(g *pipeGrave) {
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
		pipeRecordErr()
		p.emit(g.serial, false)
		return
	}
	p.inflight[cseq] = &pipeInflight{serial: g.serial, aid: aid, deadline: time.Now().Add(p.timeout), retries: g.retries + 1, sentAt: time.Now()}
}

func (p *checkPipeline) govern() {
	total := p.resolvedCycle + p.expiredCycle
	if total > 0 {
		share := float64(p.expiredCycle) / float64(total)
		if p.emaSet {
			p.expiredEMA = p.expiredEMA*7/8 + share/8
		} else {
			p.expiredEMA, p.emaSet = share, true
		}
	}
	switch {
	case p.emaSet && p.expiredEMA < 0.02:
		p.window += pipeWindowGrow
		if p.window > pipeWindowMax {
			p.window = pipeWindowMax
		}
	case p.emaSet && p.expiredEMA > 0.10:
		p.window -= pipeWindowShrink
		if p.window < pipeWindowMin {
			p.window = pipeWindowMin
		}
	}
	p.resolvedCycle, p.expiredCycle = 0, 0
}

func (p *checkPipeline) pump(maxWait time.Duration) {
	dl := p.minDeadline()
	wait := time.Until(dl)
	if maxWait > 0 && maxWait < wait {
		wait = maxWait
	}
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	resp, got := p.readResp(time.Now().Add(wait))
	if !got {
		p.expire()
		return
	}
	p.resolve(resp)
	p.expire()
}

func (p *checkPipeline) run(jobs <-chan string) {
	var pumpCap time.Duration
	for {
		if p.cancelled() {
			return
		}
		pumpCap = 0
		for len(p.inflight) < p.window {
			if !p.tryRate() {
				pumpCap = p.nextRateDelay() + time.Millisecond
				goto readPhase
			}
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
				if !p.blockRate() {
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
		p.pump(pumpCap)
		if p.resolvedCycle+p.expiredCycle >= int64(p.window) {
			p.govern()
		}
	}
drain:
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && !p.cancelled() {
		p.pump(0)
		if p.resolvedCycle+p.expiredCycle >= int64(p.window) {
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

func (p *checkPipeline) warmup() {
	cseq := SmartPSSProfile.nextCSeq()
	req := SmartPSSProfile.buildRequest("DHGET", "/probe/p2psrv", "", true, cseq)
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	if _, err := p.conn.Write(req); err != nil {
		return
	}
	dl := time.Now().Add(pipeWarmupWait)
	for {
		p.conn.SetReadDeadline(dl)
		n, err := p.conn.Read(p.buf)
		if err != nil {
			return
		}
		if resp, perr := parseDHResponse(p.buf[:n]); perr == nil {
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
