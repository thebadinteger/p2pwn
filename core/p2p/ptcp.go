package p2p

import (
	"encoding/binary"
	"fmt"
	"sync"
)

const PTCPMagic = "PTCP"

type PTCPPacket struct {
	Sent uint32
	Recv uint32
	PID  uint32
	LMID uint32
	RMID uint32
	Body []byte // raw body after 24-byte header
}

func (p *PTCPPacket) Serialize() []byte {
	buf := make([]byte, 24)
	copy(buf[0:4], PTCPMagic)
	binary.BigEndian.PutUint32(buf[4:8], p.Sent)
	binary.BigEndian.PutUint32(buf[8:12], p.Recv)
	binary.BigEndian.PutUint32(buf[12:16], p.PID)
	binary.BigEndian.PutUint32(buf[16:20], p.LMID)
	binary.BigEndian.PutUint32(buf[20:24], p.RMID)
	return append(buf, p.Body...)
}

func ParsePTCPPacket(data []byte) (*PTCPPacket, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("packet too short: %d", len(data))
	}
	if string(data[0:4]) != PTCPMagic {
		return nil, fmt.Errorf("invalid magic: %s", string(data[0:4]))
	}
	return &PTCPPacket{
		Sent: binary.BigEndian.Uint32(data[4:8]),
		Recv: binary.BigEndian.Uint32(data[8:12]),
		PID:  binary.BigEndian.Uint32(data[12:16]),
		LMID: binary.BigEndian.Uint32(data[16:20]),
		RMID: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

type PTCPSession struct {
	mu    sync.Mutex
	Sent  uint32
	Recv  uint32
	Count uint32
	ID    uint32
	RMID  uint32
}

func NewPTCPSession() *PTCPSession {
	return &PTCPSession{}
}

func (s *PTCPSession) Send(body []byte) *PTCPPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := uint32(0x0002FFFF)
	if !isSYNBody(body) {
		pid = 0x0000FFFF - s.Count
	}
	p := &PTCPPacket{
		Sent: s.Sent,
		Recv: s.Recv,
		PID:  pid,
		LMID: s.ID,
		RMID: s.RMID,
		Body: body,
	}
	s.Sent += uint32(len(body))
	s.ID++
	if !isSYNBody(body) && len(body) > 0 {
		s.Count++
	}
	return p
}

func (s *PTCPSession) Receive(p *PTCPPacket) *PTCPPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Sent+uint32(len(p.Body)) > s.Recv {
		s.Recv = p.Sent + uint32(len(p.Body))
	}
	s.RMID = p.LMID
	return p
}

func isSYNBody(body []byte) bool {
	return len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00
}

func MakeSYNBody() []byte {
	return []byte{0x00, 0x03, 0x01, 0x00}
}

func MakeSignReqBody() []byte {
	return []byte{0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func MakeAuthReqBody(sign []byte) []byte {
	body := []byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(body, sign...)
}

func MakeFinalBody() []byte {
	return []byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func MakeHeartbeatBody() []byte {
	return []byte{
		0x13, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func MakePayloadBody(realm uint32, data []byte) []byte {
	length := uint32(len(data)) | 0x10000000
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], length)
	binary.BigEndian.PutUint32(hdr[4:8], realm)
	binary.BigEndian.PutUint32(hdr[8:12], 0)
	return append(hdr, data...)
}

func ParsePayloadBody(body []byte) (realm uint32, payload []byte, err error) {
	if len(body) < 12 {
		return 0, nil, fmt.Errorf("payload body too short: %d", len(body))
	}
	length := binary.BigEndian.Uint32(body[0:4])
	realm = binary.BigEndian.Uint32(body[4:8])
	pad := binary.BigEndian.Uint32(body[8:12])
	if pad != 0 {
		return 0, nil, fmt.Errorf("invalid padding: %d", pad)
	}
	actualLen := length & 0x0FFFFFFF
	payload = body[12:]
	if uint32(len(payload)) != actualLen {
		return 0, nil, fmt.Errorf("payload length mismatch: expected %d, got %d", actualLen, len(payload))
	}
	return realm, payload, nil
}
