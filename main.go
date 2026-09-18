package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/thebadinteger/p2pwn/core"
)

var (
	colRed     = color.New(color.FgHiRed)
	colWhite   = color.New(color.FgWhite)
	colHiWhite = color.New(color.FgHiWhite)
)

func xorDecode(data []byte, key byte) string {
	dec := make([]byte, len(data))
	for i, b := range data {
		dec[i] = b ^ key
	}
	return string(dec)
}

func printHelp() {
	nowStr := time.Now().Format("15:04:05")
	colRed.Printf("[%s] p2pwn\n", nowStr)
	colWhite.Printf("[?] Dahua cameras security scanner via P2P\n")
	fmt.Printf("[-i, --input] Input file or specific target(s)\n")
	fmt.Printf("Format:\n")
	fmt.Printf("XXXXXXXXXX > Prefix\n")
	fmt.Printf("XXXXXXXXXXYYYYY > S/N\n")
	fmt.Printf("[-o, --output] Output folder for results\n")
	fmt.Printf("Default > DD-MM-YYYY_HH-MM-SS\n")
	fmt.Printf("If doesn't exist, will be created\n")
	fmt.Printf("[-t, --threads] Number of threads for scanning\n")
	fmt.Printf("Default > 100\n")
	fmt.Printf("[-c, --config] Path to config file\n")
	fmt.Printf("Default > config.toml\n")
	fmt.Printf("[-?, -h, --help] Get general help\n")
	enc := []byte{0xF0, 0xEC, 0xFB, 0xE7, 0xDD, 0x98, 0xF6, 0x8B, 0xCC, 0xC2, 0xDF, 0xC3, 0xDE, 0xC9, 0x85, 0xC8, 0xC4, 0xC6, 0x84, 0xDF, 0xC3, 0xCE, 0xC9, 0xCA, 0xCF, 0xC2, 0xC5, 0xDF, 0xCE, 0xCC, 0xCE, 0xD9}
	colHiWhite.Printf("%s\n", xorDecode(enc, 0xAB))
}

func printErrorAndExit(err string) {
	colRed.Printf("[!] %s\n", err)
	os.Exit(1)
}

func isDirReadOnly(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}
	tmpFile := filepath.Join(dir, ".p2pwn_tmp")
	f, err := os.Create(tmpFile)
	if err != nil {
		return os.IsPermission(err)
	}
	f.Close()
	os.Remove(tmpFile)
	return false
}

func main() {
	core.InitConsole()
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		return
	}

	var input string
	var output string
	threads := 100
	configPath := "config.toml"
	showHelp := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-i", "--input":
			if i+1 < len(args) {
				input = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				output = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &threads)
				i++
			}
		case "-c", "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "-h", "-?", "--help":
			showHelp = true
		}
	}

	if showHelp {
		printHelp()
		return
	}

	if input == "" {
		printErrorAndExit("No input file specified")
	}

	// Parse input
	var targets []string
	inputSource := input

	// Check if input is file
	if _, err := os.Stat(input); err == nil {
		content, err := os.ReadFile(input)
		if err != nil {
			printErrorAndExit(fmt.Sprintf("Cannot read input file: %s", err))
		}
		trimmed := strings.TrimSpace(string(content))
		if trimmed == "" {
			printErrorAndExit("Empty input")
		}

		// Split by lines and commas
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					targets = append(targets, part)
				}
			}
		}
	} else {
		// Treat input as comma-separated targets
		for _, part := range strings.Split(input, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				targets = append(targets, part)
			}
		}
	}

	if len(targets) == 0 {
		printErrorAndExit("Empty input")
	}

	seen := make(map[string]struct{}, len(targets))
	uniq := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
	}
	targets = uniq

	// Determine output dir
	if output == "" {
		output = time.Now().Format("02-01-2006_15-04-05")
	}

	if isDirReadOnly(output) {
		printErrorAndExit("Output folder is read-only")
	}

	// Load config
	isDefaultConfig := (configPath == "config.toml")
	cfg, err := core.LoadConfig(configPath, isDefaultConfig)
	if err != nil {
		printErrorAndExit(err.Error())
	}

	// Run scanner
	scanner := core.NewScanner(targets, cfg, threads, output, inputSource)
	scanner.Run()
}
