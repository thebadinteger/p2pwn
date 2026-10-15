package core

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

func parseEncryptPub(pub string) (*big.Int, int, error) {
	var hexN, hexE string
	for _, part := range strings.Split(pub, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "N":
			hexN = strings.TrimSpace(kv[1])
		case "E":
			hexE = strings.TrimSpace(kv[1])
		}
	}
	if hexN == "" || hexE == "" {
		return nil, 0, fmt.Errorf("bad pub format")
	}
	n := new(big.Int)
	if _, ok := n.SetString(hexN, 16); !ok {
		return nil, 0, fmt.Errorf("bad pub modulus")
	}
	e := 0
	if _, err := fmt.Sscanf(hexE, "%x", &e); err != nil || e <= 0 {
		return nil, 0, fmt.Errorf("bad pub exponent")
	}
	return n, e, nil
}

// rsa wraps a fresh aes key the device unwraps it with its private key
func rsaWrapKey(n *big.Int, e int, key []byte) (string, error) {
	pub := &rsa.PublicKey{N: n, E: e}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(wrapped), nil
}

func aesECBEncrypt(key, plain []byte) []byte {
	if r := len(plain) % aes.BlockSize; r != 0 {
		plain = append(plain, make([]byte, aes.BlockSize-r)...)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
	}
	return out
}

func aesECBDecrypt(key []byte, b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad cipher length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], raw[i:i+aes.BlockSize])
	}
	// zeropadding leaves nuls json never ends with one
	return bytes.TrimRight(out, "\x00"), nil
}

// fetches the live rsa key no secrets needed it is public by design
func securityEncryptPub(conn *rpc2ConnSession, sess any, cookie string) (*big.Int, int, error) {
	r, _, err := conn.post("/RPC2", map[string]any{
		"method": "Security.getEncryptInfo", "params": nil, "id": 90, "session": sess,
	}, cookie)
	if err != nil {
		return nil, 0, err
	}
	params, _ := r["params"].(map[string]any)
	pub, _ := params["pub"].(string)
	if pub == "" {
		return nil, 0, fmt.Errorf("no pub in encrypt info")
	}
	return parseEncryptPub(pub)
}

func securitySetConfig(conn *rpc2ConnSession, sess any, cookie string, name string, table any) (map[string]any, error) {
	n, e, err := securityEncryptPub(conn, sess, cookie)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	salt, err := rsaWrapKey(n, e, key)
	if err != nil {
		return nil, err
	}
	inner, _ := json.Marshal(map[string]any{"name": name, "table": table})
	content := base64.StdEncoding.EncodeToString(aesECBEncrypt(key, inner))
	r, _, err := conn.post("/RPC2", map[string]any{
		"method": "Security.setConfig",
		"params": map[string]any{"salt": salt, "cipher": "AES-128", "content": content},
		"id":     91, "session": sess,
	}, cookie)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("security set rejected: %v", r["error"])
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return map[string]any{"result": true}, nil
	}
	cipherText, _ := params["content"].(string)
	if cipherText == "" {
		return map[string]any{"result": true}, nil
	}
	plain, err := aesECBDecrypt(key, cipherText)
	if err != nil {
		return nil, fmt.Errorf("answer undecryptable: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(plain, &out); err != nil {
		var arr []any
		if jerr := json.Unmarshal(plain, &arr); jerr != nil {
			return nil, fmt.Errorf("answer bad json: %v", jerr)
		}
		return map[string]any{"result": true, "params": arr}, nil
	}
	return out, nil
}
