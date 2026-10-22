package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type inputSink struct {
	targets  []string
	provided []ProvidedCred
	seen     map[string]struct{}
}

func newInputSink() *inputSink {
	return &inputSink{seen: map[string]struct{}{}}
}

func (s *inputSink) addSerial(serial string) {
	if serial == "" {
		return
	}
	if _, ok := s.seen[serial]; ok {
		return
	}
	s.seen[serial] = struct{}{}
	s.targets = append(s.targets, serial)
}

// later file overrides earlier creds
func (s *inputSink) addCred(c ProvidedCred) {
	if c.Serial == "" || c.Login == "" {
		return
	}
	s.addSerial(c.Serial)
	for i := range s.provided {
		if s.provided[i].Serial == c.Serial {
			s.provided[i] = c
			return
		}
	}
	s.provided = append(s.provided, c)
}

func (s *inputSink) addToken(tok string) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return
	}
	if c, ok := ParseCredToken(tok); ok {
		s.addCred(c)
		return
	}
	s.addSerial(tok)
}

func (s *inputSink) addPlain(content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "<") {
			s.addXML([]byte(line))
			continue
		}
		if s.addDhscpRow(line) {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			s.addToken(part)
		}
	}
}

// dhscp row model then prefix or serial ip optional
func (s *inputSink) addDhscpRow(line string) bool {
	cols := splitCSVLine(line)
	if len(cols) < 2 || len(cols) > 4 {
		return false
	}
	model := strings.TrimSpace(cols[0])
	target := strings.TrimSpace(cols[1])
	if !looksLikeDhscpModel(model) || !looksLikeDhscpTarget(target) {
		return false
	}
	s.addSerial(target)
	return true
}

func looksLikeDhscpModel(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if looksLikeDhscpTarget(s) {
		return false
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// 10 char prefix or full serial
func looksLikeDhscpTarget(s string) bool {
	if len(s) < 10 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func (s *inputSink) addXML(data []byte) {
	creds, serials := ParseDeviceXML(data)
	for _, c := range creds {
		s.addCred(c)
	}
	for _, sn := range serials {
		s.addSerial(sn)
	}
}

func (s *inputSink) addCSV(data []byte) {
	creds, serials := ParsePwnedCSV(data)
	for _, c := range creds {
		s.addCred(c)
	}
	for _, sn := range serials {
		s.addSerial(sn)
	}
}

func (s *inputSink) addFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return s.addDir(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".xml":
		s.addXML(data)
	case ".csv":
		s.addCSV(data)
	default:
		s.addPlain(string(data))
	}
	return nil
}

func (s *inputSink) addDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable entry must not kill the whole walk
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		_ = s.addFile(path)
		return nil
	})
}

func LoadInput(arg string) (targets []string, provided []ProvidedCred, err error) {
	sink := newInputSink()

	if _, statErr := os.Stat(arg); statErr == nil {
		if err := sink.addFile(arg); err != nil {
			return nil, nil, err
		}
	} else if strings.ContainsAny(arg, `/\`) || filepath.Ext(arg) != "" {
		return nil, nil, fmt.Errorf("Input file not found: %s", arg)
	} else {
		sink.addPlain(arg)
	}

	if len(sink.targets) == 0 {
		return nil, nil, fmt.Errorf("Empty input")
	}
	return sink.targets, sink.provided, nil
}
