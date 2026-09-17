package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type SDKClient struct {
	tunnel *PTCPTunnel
	user   string
	pass   string
}

func NewSDKClient(tunnel *PTCPTunnel, user, pass string) *SDKClient {
	return &SDKClient{
		tunnel: tunnel,
		user:   user,
		pass:   pass,
	}
}

func (s *SDKClient) loginOnBind(realm uint32) (uint32, error) {
	if err := s.tunnel.SendDataWithRealm(loginPacket(s.user, s.pass), realm); err != nil {
		return realm, err
	}

	resp, err := s.tunnel.readDataSkipDisc(realm, 10*time.Second)
	if err != nil {
		return realm, err
	}
	if len(resp) < 10 {
		return realm, fmt.Errorf("login response too short (%d bytes)", len(resp))
	}
	if resp[8] == 0 {
		return realm, nil
	}

	if resp[8] == 1 {
		if cr, crnd := parseChallengeBody(resp); cr != "" && crnd != "" {
			newRealm, err := s.loginWithHashNewRealm(cr, crnd)
			return newRealm, err
		}
	}

	return realm, fmt.Errorf("login failed: code %d/%d", resp[8], resp[9])
}

func loginPacket(user, pass string) []byte {
	ul := []byte(user)
	pl := []byte(pass)
	var creds [16]byte
	copy(creds[:8], ul)
	copy(creds[8:], pl)

	pktLen := 24 + len(ul) + len(pl)
	ts := fmt.Sprintf("%d", time.Now().Unix())

	cmd := make([]byte, 0, 32+len(ul)+len(pl)+len(ts)+4)
	cmd = append(cmd, 0xa0, 0x00, 0x00, 0x60, byte(pktLen), 0x00, 0x00, 0x00)
	cmd = append(cmd, creds[:]...)
	cmd = append(cmd, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa1, 0xaa)
	cmd = append(cmd, ul...)
	cmd = append(cmd, "&&"...)
	cmd = append(cmd, pl...)
	cmd = append(cmd, []byte("\x00Random:"+ts+"\r\n\r\n")...)
	return cmd
}

func (s *SDKClient) Login() error {
	realm := rand.Uint32()
	if err := s.tunnel.doBindWithTarget(realm, "127.0.0.1:37777"); err != nil {
		return fmt.Errorf("bind 37777: %w", err)
	}
	defer s.tunnel.DisconnectRealm(realm)
	_, err := s.loginOnBind(realm)
	return err
}

func buildHashLoginPacket(user, hash string) []byte {
	creds := user + "&&" + hash
	buf := make([]byte, 12+len(creds))
	buf[0] = 0x05
	buf[1] = 0x02
	buf[2] = 0x09
	buf[3] = 0x08
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(creds)))
	buf[6] = 0x00
	buf[7] = 0x00
	buf[8] = 0xa1
	buf[9] = 0xaa
	copy(buf[10:], creds)
	return buf
}

func parseChallengeBody(body []byte) (realm, random string) {
	text := string(body)

	realmPrefix := "Realm:"
	if idx := strings.Index(text, realmPrefix); idx >= 0 {
		afterRealm := text[idx+len(realmPrefix):]
		if end := strings.Index(afterRealm, "\r\n"); end >= 0 {
			realm = strings.TrimSpace(afterRealm[:end])
		}
	}

	randomPrefix := "Random:"
	if idx := strings.Index(text, randomPrefix); idx >= 0 {
		afterRandom := text[idx+len(randomPrefix):]
		if end := strings.Index(afterRandom, "\r\n"); end >= 0 {
			random = strings.TrimSpace(afterRandom[:end])
		}
	}
	return
}

func (s *SDKClient) loginWithHashNewRealm(challengeRealm, challengeRandom string) (uint32, error) {
	realm := rand.Uint32()
	if err := s.tunnel.doBindWithTarget(realm, "127.0.0.1:37777"); err != nil {
		return realm, fmt.Errorf("bind 37777: %w", err)
	}

	if ch, err := s.tunnel.readOneDataForRealm(realm, time.Second); err == nil && len(ch) > 0 {
		if newCR, newRand := parseChallengeBody(ch); newCR != "" && newRand != "" {
			challengeRealm = newCR
			challengeRandom = newRand
		}
	}

	fullHash := SDKLoginHash(s.user, s.pass, challengeRealm, challengeRandom)
	if err := s.tunnel.SendDataWithRealm(buildHashLoginPacket(s.user, fullHash), realm); err != nil {
		return realm, fmt.Errorf("send hash login: %w", err)
	}

	resp, err := s.tunnel.ReadDataForRealm(realm, 10*time.Second)
	if err != nil {
		return realm, fmt.Errorf("read hash login: %w", err)
	}
	if len(resp) < 10 {
		return realm, fmt.Errorf("hash login short (%d bytes)", len(resp))
	}
	if resp[8] != 0 {
		return realm, fmt.Errorf("hash login code %d/%d", resp[8], resp[9])
	}
	return realm, nil
}

func sdkCmdGetSerial() []byte {
	return []byte{
		0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func sdkCmdGetDeviceType() []byte {
	return []byte{
		0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func sdkCmdGetChannels() []byte {
	return []byte{
		0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func (s *SDKClient) GetDeviceInfo() (serial, model string, channels int, err error) {
	realm := rand.Uint32()
	if err := s.tunnel.doBindWithTarget(realm, "127.0.0.1:37777"); err != nil {
		return "", "", 0, fmt.Errorf("bind: %w", err)
	}
	defer s.tunnel.DisconnectRealm(realm)

	if err := s.loginOnBindSingle(realm); err != nil {
		return "", "", 0, err
	}

	if resp, e := s.tunnel.SDKExchangeSingle(realm, sdkCmdGetSerial(), 5*time.Second); e == nil && len(resp) > 32 {
		serial = strings.TrimRight(string(resp[32:]), "\x00")
	}

	if resp, e := s.tunnel.SDKExchangeSingle(realm, sdkCmdGetDeviceType(), 5*time.Second); e == nil && len(resp) > 32 {
		model = strings.TrimRight(string(resp[32:]), "\x00")
	}

	if resp, e := s.tunnel.SDKExchangeSingle(realm, sdkCmdGetChannels(), 5*time.Second); e == nil && len(resp) > 32 {
		content := strings.TrimRight(string(resp[32:]), "\x00")
		channels = strings.Count(content, "&&") + 1
	}
	if channels == 0 {
		channels = 1
	}

	return
}

func (s *SDKClient) loginOnBindSingle(realm uint32) error {
	if err := s.tunnel.SendDataWithRealm(loginPacket(s.user, s.pass), realm); err != nil {
		return err
	}
	resp, err := s.tunnel.readOneDataForRealm(realm, 10*time.Second)
	if err != nil {
		return err
	}
	if len(resp) < 10 {
		return fmt.Errorf("login response too short (%d bytes)", len(resp))
	}
	if resp[8] != 0 {
		return fmt.Errorf("login failed: code %d/%d", resp[8], resp[9])
	}
	return nil
}

func (s *SDKClient) GetSnapshot(channel int) ([]byte, error) {
	ch := byte(0)
	if channel > 0 {
		ch = byte(channel - 1)
	}

	cmd := []byte{
		0x11, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x00,
		ch,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
		ch,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	realm := rand.Uint32()
	if err := s.tunnel.doBindWithTarget(realm, "127.0.0.1:37777"); err != nil {
		return nil, fmt.Errorf("snapshot bind: %w", err)
	}
	defer s.tunnel.DisconnectRealm(realm)

	loginRealm, err := s.loginOnBind(realm)
	if err != nil {
		return nil, fmt.Errorf("snapshot login: %w", err)
	}
	if loginRealm != realm {
		defer s.tunnel.DisconnectRealm(loginRealm)
		realm = loginRealm
	}

	s.tunnel.readDataSkipDisc(realm, 50*time.Millisecond)

	if err := s.tunnel.SendDataWithRealm(cmd, realm); err != nil {
		return nil, fmt.Errorf("snapshot send: %w", err)
	}

	var data []byte
	for {
		chunk, err := s.tunnel.readDataSkipDisc(realm, 5*time.Second)
		if err != nil {
			if len(data) > 0 {
				break
			}
			return nil, fmt.Errorf("snapshot read: %w", err)
		}
		data = append(data, chunk...)
		if containsJPEGEnd(data) {
			for {
				tail, tailErr := s.tunnel.readDataSkipDisc(realm, 50*time.Millisecond)
				if tailErr != nil {
					break
				}
				data = append(data, tail...)
			}
			break
		}
	}

	if len(data) >= 32 {
		data = data[32:]
	}

	data = stripSnapshotGarbage(data, ch)

	if soi := bytes.Index(data, []byte{0xff, 0xd8}); soi >= 0 {
		data = data[soi:]
		if eoi := bytes.LastIndex(data, []byte{0xff, 0xd9}); eoi >= 0 {
			data = data[:eoi+2]
		}
	}

	return data, nil
}

func containsJPEGEnd(data []byte) bool {
	return bytes.Contains(data, []byte{0xff, 0xd9})
}

func stripSnapshotGarbage(data []byte, ch byte) []byte {
	garbage1 := []byte{0x0a, ch, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00}
	garbage2 := []byte{0xbc, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, ch}

	for {
		idx := bytes.Index(data, garbage1)
		if idx < 0 {
			break
		}
		start := idx - 24
		if start < 0 {
			start = 0
		}
		end := idx + len(garbage1)
		if end > len(data) {
			end = len(data)
		}
		data = append(data[:start], data[end:]...)
	}
	for {
		idx := bytes.Index(data, garbage2)
		if idx < 0 {
			break
		}
		end := idx + 32
		if end > len(data) {
			end = len(data)
		}
		data = append(data[:idx], data[end:]...)
	}
	return data
}
