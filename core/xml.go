package core

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strings"
)

const (
	XOR_CONST = 0x33941615D
	XOR_MASK  = 0xFFFFFFFF
	SEED0     = 0xDEADBEEF
)

func nextSeed(seed uint32) uint32 {
	return uint32((uint64(seed) + XOR_CONST) & XOR_MASK)
}

func applyCore(buf []byte, seed0 uint32) {
	seed := nextSeed(seed0)
	n := len(buf)

	i := 0
	for i < n-3 {
		word := binary.LittleEndian.Uint32(buf[i : i+4])
		word ^= seed
		binary.LittleEndian.PutUint32(buf[i:i+4], word)
		i++
		seed = nextSeed(seed)
	}

	tailIndex := n - 3
	var seedBytes [4]byte
	for tailIndex < n {
		binary.LittleEndian.PutUint32(seedBytes[:], seed)
		for j := 0; j < 4; j++ {
			rawPos := tailIndex + j
			pos := rawPos
			if rawPos >= n {
				pos = rawPos % n
			}
			buf[pos] ^= seedBytes[j]
		}
		tailIndex++
		seed = nextSeed(seed)
	}
}

func FastEnc(password string) string {
	tail := []byte("p2pwn")
	extra := []byte("p2pwnnownsdahuacams")
	seed0 := uint32(SEED0)

	decoded := []byte(password)
	decoded = append(decoded, tail...)

	tailLenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(tailLenBuf, uint32(len(tail)))
	decoded = append(decoded, tailLenBuf...)

	decoded = append(decoded, extra...)

	extraLenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(extraLenBuf, uint32(len(extra)))
	decoded = append(decoded, extraLenBuf...)

	applyCore(decoded, seed0)

	seed0Buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seed0Buf, seed0)
	decoded = append(decoded, seed0Buf...)

	return base64.StdEncoding.EncodeToString(decoded)
}

func DecryptDevPass(blob string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	if len(data) <= 12 {
		return "", fmt.Errorf("blob too short")
	}
	seed0 := binary.LittleEndian.Uint32(data[len(data)-4:])
	rest := data[:len(data)-4]
	applyCore(rest, seed0)

	extraLen := binary.LittleEndian.Uint32(rest[len(rest)-4:])
	rest = rest[:len(rest)-4]
	if int(extraLen) > len(rest) {
		return "", fmt.Errorf("extra len %d over buffer %d", extraLen, len(rest))
	}
	rest = rest[:len(rest)-int(extraLen)]

	tailLen := binary.LittleEndian.Uint32(rest[len(rest)-4:])
	rest = rest[:len(rest)-4]
	if int(tailLen) > len(rest) {
		return "", fmt.Errorf("tail len %d over buffer %d", tailLen, len(rest))
	}
	return string(rest[:len(rest)-int(tailLen)]), nil
}

func EscapeXML(s string) string {
	var buf strings.Builder
	for _, c := range s {
		switch c {
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '&':
			buf.WriteString("&amp;")
		case '"':
			buf.WriteString("&quot;")
		case '\'':
			buf.WriteString("&apos;")
		default:
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

func BuildDeviceXMLRow(serial string, login string, encryptedPassword string) string {
	s := EscapeXML(serial)
	l := EscapeXML(login)
	b := EscapeXML(encryptedPassword)
	return "\t" + `<Device name="` + s + `" domain="` + s + `" port="37777" username="` + l + `" password="` + b + `" protocol="1" connect="19" />` + "\n"
}

type devXML struct {
	Name     string `xml:"name,attr"`
	Domain   string `xml:"domain,attr"`
	Username string `xml:"username,attr"`
	Password string `xml:"password,attr"`
}

type devManagerXML struct {
	Devices []devXML `xml:"Device"`
}

func ParseDeviceXML(data []byte) (creds []ProvidedCred, serials []string) {
	var dm devManagerXML
	var devices []devXML
	if err := xml.Unmarshal(data, &dm); err != nil {
		var d devXML
		if err2 := xml.Unmarshal(data, &d); err2 != nil {
			return nil, nil
		}
		devices = []devXML{d}
	} else {
		devices = dm.Devices
	}
	for _, dev := range devices {
		serial := strings.TrimSpace(dev.Domain)
		if serial == "" {
			continue
		}
		user := strings.TrimSpace(dev.Username)
		pass, err := DecryptDevPass(dev.Password)
		if err != nil || user == "" || pass == "" {
			serials = append(serials, serial)
			continue
		}
		creds = append(creds, ProvidedCred{Serial: serial, Login: user, Password: pass})
	}
	return creds, serials
}

func ParsePwnedCSV(data []byte) (creds []ProvidedCred, serials []string) {
	rows := splitCSV(data)
	if len(rows) == 0 {
		return nil, nil
	}
	head := strings.ToLower(strings.TrimSpace(rows[0]))
	if !strings.Contains(head, "sn") {
		return nil, nil
	}
	idx := map[string]int{}
	for i, name := range splitCSVLine(rows[0]) {
		idx[strings.ToLower(strings.TrimSpace(name))] = i
	}
	snAt, hasSN := idx["sn"]
	loginAt, hasLogin := idx["login"]
	passAt, hasPass := idx["password"]
	if !hasSN || !hasLogin || !hasPass {
		return nil, nil
	}
	for _, row := range rows[1:] {
		cols := splitCSVLine(row)
		get := func(i int) string {
			if i < 0 || i >= len(cols) {
				return ""
			}
			return strings.TrimSpace(cols[i])
		}
		serial := get(snAt)
		if serial == "" {
			continue
		}
		user, pass := get(loginAt), get(passAt)
		if user == "" || pass == "" {
			serials = append(serials, serial)
			continue
		}
		creds = append(creds, ProvidedCred{Serial: serial, Login: user, Password: pass})
	}
	return creds, serials
}

func splitCSV(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func splitCSVLine(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}
