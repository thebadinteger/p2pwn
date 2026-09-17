package core

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type ScanConfig struct {
	Timeout  interface{} `toml:"timeout"`
	Retries  interface{} `toml:"retries"`
	Generate interface{} `toml:"generate"`
	Nurses   interface{} `toml:"nurses"`
}

type PwnConfig struct {
	Protocol map[string]bool `toml:"protocol"`
	Methods  map[string]bool `toml:"methods"`
	Snapshot bool            `toml:"snapshot"`
}

type Credential struct {
	Login    string `toml:"login"`
	Password string `toml:"password"`
}

type BruteType1Config struct {
	Delay interface{} `toml:"delay"`
}

type BruteConfig struct {
	Type1       BruteType1Config `toml:"type1"`
	Credentials []Credential     `toml:"credentials"`
}

type DummyConfig struct {
	Login    string `toml:"login"`
	Password string `toml:"password"`
}

type OverlayConfig struct {
	Osd     bool     `toml:"osd"`
	Channel string   `toml:"channel"`
	Custom  []string `toml:"custom"`
}

type Config struct {
	Scan    ScanConfig    `toml:"scan"`
	Pwn     PwnConfig     `toml:"pwn"`
	Brute   BruteConfig   `toml:"brute"`
	Dummy   DummyConfig   `toml:"dummy"`
	Overlay OverlayConfig `toml:"overlay"`
	Path    string
}

const DefaultConfigData = `[scan] # Scan configuration
timeout = 5000 # Connection timeout in milliseconds
retries = 3 # Number of retries on connect
generate = 1048576 # How many S/N to generate on prefix (1-1048576)
nurses = 200 # Number of workers for checking online S/N

[pwn] # Usage of different protocols and methods
snapshot = true # Take snapshots
protocol.cgi = true # Web CGI protocol
protocol.sdk = true # 37777 SDK protocol
protocol.type1 = true # Type 1 protocol
methods.brute = true # Credentials bruteforce
methods.cve-2021-33044 = true # CVE-2021-33044
methods.cve-2021-33045 = true # CVE-2021-33045
methods.cve-2024-39943 = true # CVE-2024-39943

[brute] # Bruteforce configuration
type1.delay = 20 # Type 1 brute attempts delay in seconds
credentials = [
  { login = "admin", password = "admin" },
  { login = "admin", password = "admin123" },
  { login = "admin", password = "admin12345" },
  { login = "666666", password = "666666" },
  { login = "888888", password = "888888" },
]

[dummy] # Credentials for added dummy account
login = "p2pwn" # 5-32 alphanumeric characters
password = "p2password" # 8-32 alphanumeric characters

[overlay] # Custom overlay configuration
osd = true # Set OSD on pwned devices
channel = "p2pwn" # ChannelTitle
custom = [
  "p2pwned",
  "device is vulnerable"
] # CustomTitle (up to 5 lines)
`

type Range struct {
	Start int
	End   int
}

func ParseGenerateRanges(v interface{}) ([]Range, error) {
	switch val := v.(type) {
	case int:
		if val <= 0 || val > 1048576 {
			return nil, fmt.Errorf("invalid generate value")
		}
		return []Range{{0, val}}, nil
	case int64:
		return ParseGenerateRanges(int(val))
	case float64:
		return ParseGenerateRanges(int(val))
	case string:
		s := strings.TrimSpace(val)
		if s == "" || s == "all" {
			return []Range{{0, 1048576}}, nil
		}
		var ranges []Range
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				sub := strings.SplitN(part, "-", 2)
				start, err1 := strconv.Atoi(strings.TrimSpace(sub[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(sub[1]))
				if err1 != nil || err2 != nil || start < 0 || end > 1048576 || start >= end {
					return nil, fmt.Errorf("invalid range: %s", part)
				}
				ranges = append(ranges, Range{start, end})
			} else {
				idx, err := strconv.Atoi(part)
				if err != nil || idx < 0 || idx >= 1048576 {
					return nil, fmt.Errorf("invalid index: %s", part)
				}
				ranges = append(ranges, Range{idx, idx + 1})
			}
		}
		if len(ranges) == 0 {
			return nil, fmt.Errorf("empty generate spec")
		}
		return ranges, nil
	default:
		return nil, fmt.Errorf("invalid generate type")
	}
}

func LoadConfig(path string, isDefault bool) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if isDefault {
			if err := os.WriteFile(path, []byte(DefaultConfigData), 0644); err != nil {
				return nil, fmt.Errorf("config not found and could not create default: %s", err)
			}
			return nil, fmt.Errorf("config not found, created default config.toml")
		} else {
			return nil, fmt.Errorf("config not found")
		}
	}

	var conf Config
	_, err := toml.DecodeFile(path, &conf)
	if err != nil {
		line := 1
		if pe, ok := err.(toml.ParseError); ok {
			line = pe.Position.Line
		}
		return nil, fmt.Errorf("error in config on line %d", line)
	}

	timeoutMs, err := getIntValue(conf.Scan.Timeout)
	if err != nil || timeoutMs <= 0 {
		return nil, fmt.Errorf("invalid timeout value in config")
	}

	_, err = getIntValue(conf.Scan.Retries)
	if err != nil {
		return nil, fmt.Errorf("invalid retry value in config")
	}

	if _, err := ParseGenerateRanges(conf.Scan.Generate); err != nil {
		return nil, fmt.Errorf("invalid generate value in config: %s", err)
	}

	nursesVal, err := getIntValue(conf.Scan.Nurses)
	if err != nil || nursesVal <= 0 {
		return nil, fmt.Errorf("invalid nurses value in config")
	}

	hasProtocol := false
	for _, enabled := range conf.Pwn.Protocol {
		if enabled {
			hasProtocol = true
			break
		}
	}
	if !hasProtocol {
		return nil, fmt.Errorf("at least one protocol must be enabled in config")
	}

	hasMethod := false
	for _, enabled := range conf.Pwn.Methods {
		if enabled {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return nil, fmt.Errorf("at least one method must be enabled in config")
	}

	alphanum := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if len(conf.Dummy.Login) < 5 || len(conf.Dummy.Login) > 32 || !alphanum.MatchString(conf.Dummy.Login) {
		return nil, fmt.Errorf("invalid dummy login format in config")
	}

	if len(conf.Dummy.Password) < 8 || len(conf.Dummy.Password) > 32 || !alphanum.MatchString(conf.Dummy.Password) {
		return nil, fmt.Errorf("invalid dummy password format in config")
	}

	if len(conf.Overlay.Custom) > 5 {
		return nil, fmt.Errorf("invalid overlay custom value in config (up to 5 lines)")
	}

	conf.Path = path
	return &conf, nil
}

func getIntValue(v interface{}) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	default:
		return 0, fmt.Errorf("not an integer")
	}
}
