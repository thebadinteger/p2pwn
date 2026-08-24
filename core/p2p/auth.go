package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
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
	DefaultRandSalt = "5daf91fc5cfc1be8e081cfb08f792726"
	P2PIV           = "2z52*lk9o6HRyJrf"
)

type WSSEAuth struct {
	Username string
	UserKey  string
	Nonce    uint32
	Created  string
	Digest   string
}

func NewWSSEAuth(username, userkey string) *WSSEAuth {
	nonce := randUint32()
	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, created, username, userkey)
	h := sha1.New()
	io.WriteString(h, pwd)
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return &WSSEAuth{
		Username: username,
		UserKey:  userkey,
		Nonce:    nonce,
		Created:  created,
		Digest:   digest,
	}
}

func (a *WSSEAuth) Header() string {
	return fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"",
		a.Username, a.Digest, a.Nonce, a.Created)
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

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
	h := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, randsalt, password)))
	hexStr := fmt.Sprintf("%X", h)
	return []byte(hexStr)
}

func GetP2PNonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	return int(n.Int64())
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
	curdate := time.Now().Unix()

	msg := []byte(fmt.Sprintf("%d%d%s", nonce, curdate, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		curdate, auth, nonce, randsalt, username,
	)
}
