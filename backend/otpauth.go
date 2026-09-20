package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type parsedOtpauth struct {
	Issuer    string
	Account   string
	Secret    string
	Algorithm string
	Digits    int
	Period    int
}

func parseOtpauthURI(raw string) (*parsedOtpauth, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("otpauth URI 为空")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("otpauth URI 无效")
	}
	if !strings.EqualFold(parsed.Scheme, "otpauth") {
		return nil, fmt.Errorf("不是 otpauth URI")
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Opaque
		if index := strings.Index(host, "?"); index >= 0 {
			host = host[:index]
		}
		host = strings.Trim(host, "/")
	}
	if strings.EqualFold(host, "steam") {
		return nil, fmt.Errorf("不支持 Steam Guard")
	}
	if !strings.EqualFold(host, "totp") {
		return nil, fmt.Errorf("仅支持 totp 类型")
	}
	query := parsed.Query()
	secret := strings.TrimSpace(query.Get("secret"))
	if secret == "" {
		return nil, fmt.Errorf("URI 中缺少密钥")
	}
	encoding := strings.ToLower(strings.TrimSpace(query.Get("encoding")))
	if encoding == "hex" || encoding == "base16" {
		hexKey, hexErr := hex.DecodeString(strings.Map(func(r rune) rune {
			if r == ' ' || r == '-' {
				return -1
			}
			return r
		}, secret))
		if hexErr != nil || len(hexKey) == 0 {
			return nil, fmt.Errorf("密钥不是有效的十六进制")
		}
		secret = encodeBase32Secret(hexKey)
	} else if _, err := decodeBase32Secret(secret); err != nil {
		return nil, err
	}
	label := strings.TrimPrefix(parsed.Path, "/")
	if decoded, err := url.PathUnescape(label); err == nil {
		label = decoded
	}
	issuer := strings.TrimSpace(query.Get("issuer"))
	account := strings.TrimSpace(label)
	if account == "" {
		account = strings.TrimSpace(firstNonEmpty(query.Get("account"), query.Get("user")))
	}
	if index := strings.Index(label, ":"); index >= 0 {
		pathIssuer := strings.TrimSpace(label[:index])
		account = strings.TrimSpace(label[index+1:])
		if issuer == "" {
			issuer = pathIssuer
		}
	}
	algorithm, err := normalizeAlgorithm(firstNonEmpty(query.Get("algorithm"), query.Get("algo")))
	if err != nil {
		return nil, err
	}
	digits := defaultDigits
	if rawDigits := strings.TrimSpace(query.Get("digits")); rawDigits != "" {
		parsedDigits, convErr := strconv.Atoi(rawDigits)
		if convErr != nil {
			return nil, fmt.Errorf("位数无效")
		}
		digits, err = normalizeDigits(parsedDigits)
		if err != nil {
			return nil, err
		}
	}
	period := defaultPeriod
	rawPeriod := firstNonEmpty(query.Get("period"), query.Get("interval"), query.Get("step"), query.Get("timestep"))
	if rawPeriod != "" {
		parsedPeriod, convErr := strconv.Atoi(rawPeriod)
		if convErr != nil {
			return nil, fmt.Errorf("周期无效")
		}
		period, err = normalizePeriod(parsedPeriod)
		if err != nil {
			return nil, err
		}
	}
	return &parsedOtpauth{
		Issuer:    issuer,
		Account:   account,
		Secret:    secret,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}, nil
}

func (item *account) otpauthURI() string {
	if item == nil {
		return ""
	}
	label := otpauthLabel(item.Issuer, item.Account)
	if label == "" {
		label = "TOTP"
	}
	query := url.Values{}
	query.Set("secret", encodeBase32Secret(item.Secret))
	if item.Issuer != "" {
		query.Set("issuer", item.Issuer)
	}
	query.Set("algorithm", item.Algorithm)
	query.Set("digits", strconv.Itoa(item.Digits))
	query.Set("period", strconv.Itoa(item.Period))
	encodedLabel := strings.ReplaceAll(url.PathEscape(label), "%3A", ":")
	return "otpauth://totp/" + encodedLabel + "?" + query.Encode()
}

func otpauthLabel(issuer, account string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	switch {
	case issuer != "" && account != "":
		return issuer + ":" + account
	case account != "":
		return account
	default:
		return issuer
	}
}

func displayNameFrom(issuer, account string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	switch {
	case issuer != "" && account != "":
		return issuer + " · " + account
	case issuer != "":
		return issuer
	case account != "":
		return account
	default:
		return "TOTP"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return ""
}
