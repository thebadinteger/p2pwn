package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	DefaultUsername = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	DefaultUserKey  = "996103384cdf19179e19243e959bbf8b"
	P2PIV           = "2z52*lk9o6HRyJrf"
)

func Gen1Hash(password string) string {
	h := md5.New()
	io.WriteString(h, password)
	raw := h.Sum(nil)
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		val := (int(raw[i*2]) + int(raw[i*2+1])) % 62
		if val < 10 {
			out[i] = byte(val + 48)
		} else if val < 36 {
			out[i] = byte(val + 55)
		} else {
			out[i] = byte(val + 61)
		}
	}
	return string(out)
}

func StandardRPCHash(username, password, realm, random string) string {
	h := md5.New()
	io.WriteString(h, username)
	io.WriteString(h, ":")
	io.WriteString(h, realm)
	io.WriteString(h, ":")
	io.WriteString(h, password)
	step1 := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	h.Reset()
	io.WriteString(h, username)
	io.WriteString(h, ":")
	io.WriteString(h, random)
	io.WriteString(h, ":")
	io.WriteString(h, step1)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func SDKLoginHash(username, password, realm, random string) string {
	firstHalf := StandardRPCHash(username, password, realm, random)
	gen1 := Gen1Hash(password)
	h := md5.New()
	io.WriteString(h, username)
	io.WriteString(h, ":")
	io.WriteString(h, random)
	io.WriteString(h, ":")
	io.WriteString(h, gen1)
	secondHalf := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	return firstHalf + secondHalf
}

func GetP2PKey(username, password, randsalt string) []byte {
	h := md5.Sum(fmt.Appendf(nil, "%s:Login to %s:%s", username, randsalt, password))
	hexStr := fmt.Sprintf("%X", h)
	return []byte(hexStr)
}

func GetP2PNonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return int(n.Int64() - 1<<31)
}

func GetP2PEnc(key []byte, nonce int, data string) string {
	salt := []byte(strconv.Itoa(nonce))
	dk := pbkdf2.Key(key, salt, 20000, 32, sha256.New)

	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(P2PIV))

	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

func GetP2PDec(key []byte, nonce int, data string) string {
	salt := []byte(strconv.Itoa(nonce))
	dk := pbkdf2.Key(key, salt, 20000, 32, sha256.New)

	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(P2PIV))

	raw, _ := base64.StdEncoding.DecodeString(data)
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

func GetP2PAuth(username string, key []byte, nonce int, payload, randsalt string) string {
	return GetP2PAuthAt(username, key, nonce, payload, randsalt, time.Now().Unix())
}

func GetP2PAuthAt(username string, key []byte, nonce int, payload, randsalt string, created int64) string {
	msg := fmt.Appendf(nil, "%d%d%s", nonce, created, payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		created, auth, nonce, randsalt, username,
	)
}

const (
	DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
	DEVINFO_IV  = "MydvJw*Iw1w&i^kk"
)

func DecryptDevInfo(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return out, nil
}
