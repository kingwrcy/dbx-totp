package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type account struct {
	ID        string
	Name      string
	Issuer    string
	Account   string
	Secret    []byte
	Algorithm string
	Digits    int
	Period    int
}

func (item *account) wipe() {
	if item == nil {
		return
	}
	for i := range item.Secret {
		item.Secret[i] = 0
	}
	item.Secret = nil
}

func (item *account) fingerprint() string {
	if item == nil {
		return ""
	}
	return strings.Join([]string{
		encodeBase32Secret(item.Secret),
		item.Issuer,
		item.Account,
		item.Algorithm,
		strconv.Itoa(item.Digits),
		strconv.Itoa(item.Period),
	}, "\x00")
}

func (item *account) codeAt(now time.Time) (string, int, error) {
	code, err := generateTOTP(item.Secret, now, item.Period, item.Digits, item.Algorithm)
	if err != nil {
		return "", 0, err
	}
	return code, remainingSeconds(now, item.Period), nil
}

func (item *account) publicCode(now time.Time) (map[string]any, error) {
	code, remaining, err := item.codeAt(now)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":            item.ID,
		"code":          code,
		"digits":        item.Digits,
		"period":        item.Period,
		"remainingSecs": remaining,
		"issuer":        item.Issuer,
		"account":       item.Account,
		"algorithm":     item.Algorithm,
		"name":          item.Name,
	}, nil
}

func accountFromParsed(parsed parsedOtpauth, id string) (*account, error) {
	return accountFromRecord(vaultRecord{
		ID:        id,
		Issuer:    parsed.Issuer,
		Account:   parsed.Account,
		Name:      displayNameFrom(parsed.Issuer, parsed.Account),
		Secret:    parsed.Secret,
		Algorithm: parsed.Algorithm,
		Digits:    parsed.Digits,
		Period:    parsed.Period,
	})
}

func accountFromRecord(record vaultRecord) (*account, error) {
	algorithm, err := normalizeAlgorithm(record.Algorithm)
	if err != nil {
		return nil, err
	}
	digits, err := normalizeDigits(record.Digits)
	if err != nil {
		return nil, err
	}
	period, err := normalizePeriod(record.Period)
	if err != nil {
		return nil, err
	}
	key, err := decodeBase32Secret(record.Secret)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(record.ID)
	if id == "" {
		id = newAccountID()
	}
	name := strings.TrimSpace(record.Name)
	if name == "" {
		name = displayNameFrom(record.Issuer, record.Account)
	}
	return &account{
		ID:        id,
		Name:      name,
		Issuer:    strings.TrimSpace(record.Issuer),
		Account:   strings.TrimSpace(record.Account),
		Secret:    key,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}, nil
}

func newAccountID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

func parseParams(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return map[string]any{}, nil
	}
	return values, nil
}

func asMap(value any) map[string]any {
	mapped, _ := value.(map[string]any)
	return mapped
}

func firstString(source map[string]any, keys ...string) string {
	if source == nil {
		return ""
	}
	for _, key := range keys {
		if text := stringify(source[key]); text != "" {
			return text
		}
	}
	return ""
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func toInt(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case float64:
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return 0, fmt.Errorf("空值")
		}
		return strconv.Atoi(text)
	default:
		return 0, fmt.Errorf("不是数字")
	}
}
