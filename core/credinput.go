package core

import "strings"

type ProvidedCred struct {
	Serial   string
	Login    string
	Password string
}

func ParseCredToken(tok string) (ProvidedCred, bool) {
	parts := strings.SplitN(strings.TrimSpace(tok), ":", 3)
	if len(parts) != 3 {
		return ProvidedCred{}, false
	}
	serial := strings.TrimSpace(parts[0])
	login := strings.TrimSpace(parts[1])
	password := strings.TrimSpace(parts[2])
	if serial == "" || login == "" {
		return ProvidedCred{}, false
	}
	return ProvidedCred{Serial: serial, Login: login, Password: password}, true
}
