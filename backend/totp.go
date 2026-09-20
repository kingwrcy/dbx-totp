package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
	"unicode"
)

const (
	defaultAlgorithm = "SHA1"
	defaultDigits    = 6
	defaultPeriod    = 30
	minPeriod        = 1
	maxPeriod        = 300
)

func encodeBase32Secret(key []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(key), "=")
}

func decodeBase32Secret(secret string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)
	if cleaned == "" {
		return nil, fmt.Errorf("密钥为空")
	}
	switch len(cleaned) % 8 {
	case 2:
		cleaned += "======"
	case 4:
		cleaned += "===="
	case 5:
		cleaned += "==="
	case 7:
		cleaned += "="
	case 0:
	default:
		return nil, fmt.Errorf("密钥不是有效的 Base32")
	}
	key, err := base32.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("密钥不是有效的 Base32")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("密钥为空")
	}
	return key, nil
}

func normalizeAlgorithm(value string) (string, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(value))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	cleaned = strings.ReplaceAll(cleaned, "HMAC", "")
	switch cleaned {
	case "", "SHA1":
		return "SHA1", nil
	case "SHA256":
		return "SHA256", nil
	case "SHA512":
		return "SHA512", nil
	default:
		return "", fmt.Errorf("不支持的算法")
	}
}

func normalizeDigits(value int) (int, error) {
	if value == 0 {
		return defaultDigits, nil
	}
	if value != 6 && value != 8 {
		return 0, fmt.Errorf("位数只支持 6 或 8")
	}
	return value, nil
}

func normalizePeriod(value int) (int, error) {
	if value == 0 {
		return defaultPeriod, nil
	}
	if value < minPeriod || value > maxPeriod {
		return 0, fmt.Errorf("周期必须在 %d 到 %d 秒之间", minPeriod, maxPeriod)
	}
	return value, nil
}

func hashFunc(algorithm string) func() hash.Hash {
	switch algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

func generateTOTP(secret []byte, now time.Time, period int, digits int, algorithm string) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("密钥为空")
	}
	period, err := normalizePeriod(period)
	if err != nil {
		return "", err
	}
	digits, err = normalizeDigits(digits)
	if err != nil {
		return "", err
	}
	algorithm, err = normalizeAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	counter := uint64(now.Unix()) / uint64(period)
	return generateHOTP(secret, counter, digits, algorithm)
}

func generateHOTP(secret []byte, counter uint64, digits int, algorithm string) (string, error) {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(hashFunc(algorithm), secret)
	if _, err := mac.Write(msg[:]); err != nil {
		return "", fmt.Errorf("计算验证码失败")
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := int(sum[offset]&0x7f)<<24 |
		int(sum[offset+1]&0xff)<<16 |
		int(sum[offset+2]&0xff)<<8 |
		int(sum[offset+3]&0xff)
	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binCode%mod), nil
}

func remainingSeconds(now time.Time, period int) int {
	p := int64(period)
	if p <= 0 {
		p = int64(defaultPeriod)
	}
	unix := now.Unix()
	return int(p - (unix % p))
}
