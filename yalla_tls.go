package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

var rsaPubKeyB64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAik19fj8zJnG7Ub50NvgLObo7KWkEQgXd7AcK9KsIETw/IvCsNc3SsbZqK9qpb+Ulv4kKMe1L6249+3fMLLzSpLtsb2k0cyRk3eKW0uyj8483HI2iSvAr1DIgNzvUXMbIAXSizw4IMQAejUKRbLh4w+lKVWU/6nSuMZNhpzswNPJqegItrEhIRK0tQ78W0lhFCvS3ggRbbFN7Oh/CNM843ZvS9tiFPS66kmmjimxxyAXKAPXvuMfJ9wuLXdkeBob87uGV16yW74835pux0GSRbHSmsNaZiZ5KJBkSEOE1HDsaYiSUQz3ByGGBnw9nah91ZnXxYuk55JvWcyg+Wuv9RwIDAQAB"

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func aesEncryptB64(aesKey []byte, plaintext []byte) string {
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, 16)
	rand.Read(iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pkcs7Pad(plaintext, 16)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)
	combined := append(iv, encrypted...)
	return base64.StdEncoding.EncodeToString(combined)
}

func buildPayload(mobile, password string) (map[string]string, string) {
	aesKey := make([]byte, 24)
	rand.Read(aesKey)
	aesKeyB64 := base64.StdEncoding.EncodeToString(aesKey)

	payload := map[string]interface{}{
		"mobile":     mobile,
		"areaCode":   "964",
		"password":   md5hex(password),
		"languageId": 1,
	}
	payloadBytes, _ := json.Marshal(payload)
	paramJSON := aesEncryptB64(aesKey, payloadBytes)

	baseParam := map[string]interface{}{
		"timeSpan":   time.Now().UnixMilli(),
		"nonce":      fmt.Sprintf("%x_%s", time.Now().UnixNano(), "abcdefghijklmno"),
		"token":      nil,
		"version":    "1.2.0.2",
		"plateType":  1,
		"deviceType": 4,
	}
	baseParamBytes, _ := json.Marshal(baseParam)
	baseParamB64 := aesEncryptB64(aesKey, baseParamBytes)

	headers := map[string]string{
		"User-Agent":      "YallaLudoHD-Android-187853807",
		"Accept":          "*/*",
		"Content-Type":    "application/json",
		"BlowFishString":  aesKeyB64,
		"BaseParamString": baseParamB64,
		"Version":         "1.2.0.2",
		"X-Unity-Version": "2022.3.62f2c1",
	}

	body := `{"paramJsonString":"` + paramJSON + `"}`
	return headers, body
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println(`{"error":"usage: yalla_tls <mobile> <password>"}`)
		return
	}

	mobile := os.Args[1]
	password := os.Args[2]

	headers, body := buildPayload(mobile, password)

	// ═══ TLS Connection (stdlib فقط — بدون utls) ═══
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "account.yalla.games",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	t0 := time.Now()
	conn, err := tls.Dial("tcp", "account.yalla.games:443", config)
	if err != nil {
		result := map[string]interface{}{"error": err.Error()}
		out, _ := json.Marshal(result)
		fmt.Println(string(out))
		return
	}
	defer conn.Close()

	req := "POST /YallaGame/V2/AccountRelation/LoginByMobilePwd HTTP/1.1\r\n"
	req += "Host: account.yalla.games\r\n"
	for k, v := range headers {
		req += k + ": " + v + "\r\n"
	}
	req += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	req += "Connection: close\r\n\r\n"
	req += body

	conn.Write([]byte(req))

	resp, _ := io.ReadAll(conn)
	elapsed := time.Since(t0).Milliseconds()

	result := map[string]interface{}{
		"status":  "ok",
		"body":    string(resp),
		"elapsed": elapsed,
		"alpn":    conn.ConnectionState().NegotiatedProtocol,
	}
	out, _ := json.Marshal(result)
	fmt.Println(string(out))
}
