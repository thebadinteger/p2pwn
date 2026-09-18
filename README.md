<h1 align="center">p2pwn</h1>  
<h3 align="center">Dahua cameras security scanner via P2P</h3>  
<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00647d?style=flat&logo=go&logoColor=ffffff" alt="Go"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-green" alt="Go"/>
  <img src="https://img.shields.io/github/license/thebadinteger/p2pwn" alt="License"/>
</p>  

<div align="center"><img src="https://raw.githubusercontent.com/thebadinteger/p2pwn/refs/heads/main/preview.png" alt="Preview"></div>  

---

- [Features](#Features)
- [Installation](#Installation)
- [Usage](#Usage)
- [Configuration](#Configuration)
- [Credits](#Credits)
- [Disclaimer](#Disclaimer)

## Features:  
- Multithreaded  
- Protocol support: `CGI, SDK`  
- `Type 0/1` devices support  
- CVE and weak credential detection  
- Flexible configuration  
- Snapshots capture  
- Import XML generation for Dahua software  
- Auto OSD overlay placement  

## Installation:  
**Via Go:**  
```shell
go install github.com/thebadinteger/p2pwn@main
```  
**Build from source:**  
```shell
git clone https://github.com/thebadinteger/p2pwn.git
cd p2pwn
go build
```  
Or download the latest binary from the **[Releases page](https://github.com/thebadinteger/p2pwn/releases/latest)**.  

## Usage:  
```shell
./p2pwn -i [input] -o [output] -t [threads] (-c [config])
```  
```
[-i, --input] Input file or specific target(s)
Format:
XXXXXXXXXX > Prefix
XXXXXXXXXXYYYYY > S/N
[-o, --output] Output folder for results
Default > DD-MM-YYYY_HH-MM-SS
If doesn't exist, will be created
[-t, --threads] Number of threads for scanning
Default > 100
[-c, --config] Path to config file
Default > config.toml
[-?, -h, --help] Get general help
```  

**Input format:**  
S/N or Prefix
```
XXXXXXXXXX
XXXXXXXXXXYYYYY
```  
```
XXXXXXXXXX,XXXXXXXXXXYYYYY
```  
**Output format:**  
pwned.csv:
```
sn,model,login,password,channels,ip,vuln
```  
import_*.xml:  
*(Maximum 64 devices per file)*  
```
<?xml version="1.0" encoding="UTF-8"?>
<DeviceManager version="2.0">
        <Device name="{serial}" domain="{serial}" port="37777" username="{login}" password="{encryptedpass}" protocol="1" connect="19" />
</DeviceManager>
```  
snapshots/:  
*Special password characters are not displayed in the file name*  
```
{serial}_{login}_{password}_{model}.jpg
```  

## Configuration:  
- `config.toml`  

In the configuration, you can set up scanning and pentesting, and enable or disable check methods.  
**Default config:**  
```toml
[scan] # Scan configuration
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
```  
Tips:  
- `nurses` - The higher, the faster the S/N check (online/offline), but more packets
- `snapshot` - Takes snapshot of the first channel (Disabling it can speed up the scan)
- `protocol.cgi` - Can check CVEs and brute
- `protocol.sdk` - Can only brute (Disable to speed up the scan if not scanning NVRs)
- `protocol.type1` - Can only brute (Disable to speed up the scan if not scanning Type 1 devices)
- `methods.cve-2021-33044` - Extracts admin credentials
- `methods.cve-2021-33045` - Extracts admin credentials, adds a dummy account (fallback)
- `methods.cve-2024-39943` - Adds a dummy account
- `type1.delay` - Type 1 brute attempts delay in seconds (not recommended to change)
- `channel` - Custom channel title for OSD overlay (leave empty to not change)
- `custom` - Custom OSD overlay text (leave empty to not change)

## Credits  
Made by [badinteger](https://github.com/thebadinteger) `[GPL v3.0 License]`  
Special thanks: **[THANKS.md](THANKS.md)**  

## Disclaimer  
**This software is intended for educational and authorized testing purposes only.  
The author is not responsible for your actions or any misuse and damage caused by the software.**
