package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

func parseImportText(raw string) ([]parsedOtpauth, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if raw == "" {
		return nil, fmt.Errorf("导入内容为空")
	}
	if !strings.Contains(strings.ToLower(raw), "otpauth") && strings.Contains(raw, "%") {
		if decoded, err := url.QueryUnescape(raw); err == nil && strings.TrimSpace(decoded) != "" {
			raw = strings.TrimSpace(decoded)
		}
	}

	if accounts := parseMigrationText(raw); len(accounts) > 0 {
		return accounts, nil
	}
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		accounts, err := parseJSONImport(trimmed)
		if err != nil {
			return nil, err
		}
		if len(accounts) > 0 {
			return accounts, nil
		}
		return nil, fmt.Errorf("JSON 中未找到可用的 TOTP 账号")
	}
	if accounts := parseOtpauthFromText(raw); len(accounts) > 0 {
		return accounts, nil
	}
	if accounts := parseMigrationPayloadText(raw); len(accounts) > 0 {
		return accounts, nil
	}
	if account, err := parseTwoLineSecret(raw); err == nil {
		return []parsedOtpauth{*account}, nil
	}
	if account, err := parseBareSecret(raw); err == nil {
		return []parsedOtpauth{*account}, nil
	}
	return nil, fmt.Errorf("无法识别导入格式，请粘贴 otpauth URI、Google 导出码或未加密的备份 JSON")
}

func parseOtpauthFromText(raw string) []parsedOtpauth {
	var accounts []parsedOtpauth
	for _, uri := range extractSchemeURIs(raw, "otpauth://") {
		if strings.HasPrefix(strings.ToLower(uri), "otpauth-migration://") {
			continue
		}
		parsed, err := parseOtpauthURI(uri)
		if err != nil {
			continue
		}
		accounts = append(accounts, *parsed)
	}
	return accounts
}

func parseMigrationText(raw string) []parsedOtpauth {
	var accounts []parsedOtpauth
	for _, uri := range extractSchemeURIs(raw, "otpauth-migration://") {
		parsed, err := parseMigrationURI(uri)
		if err != nil {
			continue
		}
		accounts = append(accounts, parsed...)
	}
	return accounts
}

func parseMigrationURI(raw string) ([]parsedOtpauth, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("Google 导出 URI 无效")
	}
	if !strings.EqualFold(parsed.Scheme, "otpauth-migration") {
		return nil, fmt.Errorf("不是 Google Authenticator 导出 URI")
	}
	data := strings.TrimSpace(parsed.Query().Get("data"))
	if data == "" {
		return nil, fmt.Errorf("导出码缺少 data")
	}
	accounts := parseMigrationPayloadText(data)
	if len(accounts) == 0 {
		return nil, fmt.Errorf("导出码中未找到可用的 TOTP 账号")
	}
	return accounts, nil
}

func parseMigrationPayloadText(raw string) []parsedOtpauth {
	payload, err := decodeMigrationBytes(raw)
	if err != nil {
		return nil
	}
	accounts, err := parseMigrationPayload(payload)
	if err != nil {
		return nil
	}
	return accounts
}

func decodeMigrationBytes(raw string) ([]byte, error) {
	data := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	if data == "" {
		return nil, fmt.Errorf("导出数据为空")
	}
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(data)
		if err != nil {
			lastErr = err
			continue
		}
		if len(decoded) == 0 {
			continue
		}
		return decoded, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("导出数据不是有效的 Base64")
	}
	return nil, lastErr
}

func parseJSONImport(raw string) ([]parsedOtpauth, error) {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("JSON 无效")
	}
	if isEncryptedAegis(value) {
		return nil, fmt.Errorf("不支持加密的 Aegis 备份，请导出未加密 JSON")
	}
	var accounts []parsedOtpauth
	collectJSONAccounts(value, &accounts)
	return uniqueAccounts(accounts), nil
}

func isEncryptedAegis(value any) bool {
	root := asMap(value)
	if len(root) == 0 {
		return false
	}
	header := asMap(root["header"])
	if slots, ok := header["slots"]; ok && slots != nil {
		if items, ok := slots.([]any); ok && len(items) > 0 {
			return true
		}
	}
	if db, ok := root["db"].(string); ok && strings.TrimSpace(db) != "" {
		return true
	}
	return false
}

func collectJSONAccounts(value any, out *[]parsedOtpauth) {
	switch typed := value.(type) {
	case map[string]any:
		if account, ok := accountFromJSONMap(typed); ok {
			*out = append(*out, *account)
			return
		}
		for _, nested := range typed {
			collectJSONAccounts(nested, out)
		}
	case []any:
		for _, nested := range typed {
			collectJSONAccounts(nested, out)
		}
	case string:
		text := strings.TrimSpace(typed)
		if accounts := parseOtpauthFromText(text); len(accounts) > 0 {
			*out = append(*out, accounts...)
			return
		}
		if accounts := parseMigrationText(text); len(accounts) > 0 {
			*out = append(*out, accounts...)
		}
	}
}

func accountFromJSONMap(values map[string]any) (*parsedOtpauth, bool) {
	if totp := firstString(values, "totp", "otpauth", "otpauth_uri", "otpUrl", "otp_url"); totp != "" {
		if parsed, err := firstImportedURI(totp); err == nil {
			return parsed, true
		}
		if parsed, err := parseBareSecret(totp); err == nil {
			return parsed, true
		}
	}
	info := asMap(values["info"])
	otp := asMap(values["otp"])
	secret := jsonSecret(values)
	if secret == "" {
		secret = jsonSecret(info)
	}
	if secret == "" {
		secret = jsonSecret(otp)
	}
	if secret == "" {
		return nil, false
	}
	kind := firstNonEmpty(
		firstString(values, "type", "kind", "tokenType", "token_type", "otpType", "otp_type"),
		firstString(otp, "tokenType", "token_type", "type"),
		firstString(info, "type"),
	)
	if isSteamKind(kind) {
		return nil, false
	}
	if isHotpKind(kind) {
		return nil, false
	}
	if kind != "" && !isTotpKind(kind) && !hasTOTPHints(values, info, otp) {
		return nil, false
	}
	if kind == "" && !hasTOTPHints(values, info, otp) {
		return nil, false
	}
	issuer := firstNonEmpty(
		firstString(values, "issuer", "issuerExt", "issuer_ext", "name"),
		firstString(otp, "issuer"),
		firstString(info, "issuer"),
	)
	accountName := firstNonEmpty(
		firstString(values, "account", "label", "username", "user"),
		firstString(otp, "account", "label"),
		firstString(info, "account", "label"),
	)
	if strings.EqualFold(issuer, accountName) {
		if alt := firstString(values, "label", "account"); alt != "" && !strings.EqualFold(alt, issuer) {
			accountName = alt
		}
	}
	if accountName == "" {
		accountName = firstString(values, "name")
	}
	if issuer != "" && strings.HasPrefix(accountName, issuer) {
		accountName = strings.TrimPrefix(accountName, issuer)
		accountName = strings.TrimLeft(accountName, " :-–—")
		accountName = strings.TrimSpace(accountName)
	}
	algorithm := firstNonEmpty(
		firstString(values, "algorithm", "algo"),
		firstString(otp, "algorithm", "algo"),
		firstString(info, "algorithm", "algo"),
	)
	normalizedAlgorithm, err := normalizeAlgorithm(algorithm)
	if err != nil {
		return nil, false
	}
	digitsValue := firstJSONInt(info, otp, values, "digits")
	digits, err := normalizeDigits(digitsValue)
	if err != nil {
		return nil, false
	}
	periodValue := firstJSONInt(info, otp, values, "period", "interval", "step")
	period, err := normalizePeriod(periodValue)
	if err != nil {
		return nil, false
	}
	if _, err := decodeBase32Secret(secret); err != nil {
		return nil, false
	}
	if issuer == "" && accountName == "" {
		issuer = "TOTP"
	}
	return &parsedOtpauth{
		Issuer:    issuer,
		Account:   accountName,
		Secret:    secret,
		Algorithm: normalizedAlgorithm,
		Digits:    digits,
		Period:    period,
	}, true
}

func firstImportedURI(raw string) (*parsedOtpauth, error) {
	if accounts := parseMigrationText(raw); len(accounts) > 0 {
		return &accounts[0], nil
	}
	if parsed, err := parseOtpauthURI(raw); err == nil {
		return parsed, nil
	}
	if accounts := parseOtpauthFromText(raw); len(accounts) > 0 {
		return &accounts[0], nil
	}
	return nil, fmt.Errorf("不是 TOTP URI")
}

func jsonSecret(values map[string]any) string {
	if values == nil {
		return ""
	}
	if text := firstString(values, "secret", "secretKey", "secret_key"); text != "" {
		return text
	}
	raw, ok := values["secret"]
	if !ok {
		return ""
	}
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return ""
	}
	key := make([]byte, 0, len(items))
	for _, item := range items {
		number, err := toInt(item)
		if err != nil || number < 0 || number > 255 {
			return ""
		}
		key = append(key, byte(number))
	}
	if len(key) == 0 {
		return ""
	}
	return encodeBase32Secret(key)
}

func hasTOTPHints(maps ...map[string]any) bool {
	for _, item := range maps {
		if item == nil {
			continue
		}
		if firstString(item, "issuer", "issuerExt", "algorithm", "algo", "label", "account", "period", "digits") != "" {
			return true
		}
		if _, ok := item["digits"]; ok {
			return true
		}
		if _, ok := item["period"]; ok {
			return true
		}
	}
	return false
}

func isTotpKind(kind string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(kind))
	return cleaned == "totp" || cleaned == "otpauth"
}

func isHotpKind(kind string) bool {
	return strings.EqualFold(strings.TrimSpace(kind), "hotp")
}

func isSteamKind(kind string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(kind))
	return cleaned == "steam" || cleaned == "steamguard"
}

func firstJSONInt(sources ...any) int {
	if len(sources) == 0 {
		return 0
	}
	var keys []string
	var maps []map[string]any
	for _, source := range sources {
		switch typed := source.(type) {
		case string:
			keys = append(keys, typed)
		case map[string]any:
			maps = append(maps, typed)
		}
	}
	for _, item := range maps {
		for _, key := range keys {
			if value, ok := item[key]; ok {
				if parsed, err := toInt(value); err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}

func parseTwoLineSecret(raw string) (*parsedOtpauth, error) {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 {
		return nil, fmt.Errorf("不是两行密钥")
	}
	if _, err := decodeBase32Secret(lines[1]); err != nil {
		return nil, err
	}
	issuer := ""
	accountName := lines[0]
	if index := strings.Index(accountName, ":"); index >= 0 {
		issuer = strings.TrimSpace(accountName[:index])
		accountName = strings.TrimSpace(accountName[index+1:])
	}
	return &parsedOtpauth{
		Issuer:    issuer,
		Account:   accountName,
		Secret:    lines[1],
		Algorithm: defaultAlgorithm,
		Digits:    defaultDigits,
		Period:    defaultPeriod,
	}, nil
}

func parseBareSecret(raw string) (*parsedOtpauth, error) {
	if strings.ContainsAny(raw, ":/?{}[]\"") {
		return nil, fmt.Errorf("不是裸密钥")
	}
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' {
			return -1
		}
		return unicode.ToUpper(r)
	}, raw)
	if len(cleaned) < 16 {
		return nil, fmt.Errorf("裸密钥过短")
	}
	if _, err := decodeBase32Secret(cleaned); err != nil {
		return nil, err
	}
	return &parsedOtpauth{
		Secret:    cleaned,
		Algorithm: defaultAlgorithm,
		Digits:    defaultDigits,
		Period:    defaultPeriod,
	}, nil
}

func extractSchemeURIs(raw, prefix string) []string {
	lower := strings.ToLower(raw)
	prefixLower := strings.ToLower(prefix)
	var uris []string
	start := 0
	for {
		index := strings.Index(lower[start:], prefixLower)
		if index < 0 {
			break
		}
		index += start
		end := index
		for end < len(raw) {
			ch := raw[end]
			if ch == '"' || ch == '\'' || ch == '<' || ch == '>' || unicode.IsSpace(rune(ch)) {
				break
			}
			end++
		}
		uri := strings.TrimRight(raw[index:end], ".,);]")
		if uri != "" {
			uris = append(uris, uri)
		}
		start = end
	}
	return uris
}

func uniqueAccounts(accounts []parsedOtpauth) []parsedOtpauth {
	seen := map[string]struct{}{}
	var unique []parsedOtpauth
	for _, item := range accounts {
		key := strings.Join([]string{item.Issuer, item.Account, item.Secret, item.Algorithm, fmt.Sprintf("%d:%d", item.Digits, item.Period)}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

func parseMigrationPayload(data []byte) ([]parsedOtpauth, error) {
	fields, err := readProtoFields(data)
	if err != nil {
		return nil, err
	}
	var accounts []parsedOtpauth
	for _, field := range fields {
		if field.num != 1 || field.wire != 2 {
			continue
		}
		account, err := parseMigrationParameters(field.bytes)
		if err != nil {
			continue
		}
		accounts = append(accounts, *account)
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("导出码中未找到可用的 TOTP 账号")
	}
	return accounts, nil
}

func parseMigrationParameters(data []byte) (*parsedOtpauth, error) {
	fields, err := readProtoFields(data)
	if err != nil {
		return nil, err
	}
	var secret []byte
	var name string
	var issuer string
	algorithm := defaultAlgorithm
	digits := defaultDigits
	otpType := 2
	counter := uint64(0)
	for _, field := range fields {
		switch {
		case field.num == 1 && field.wire == 2:
			secret = append([]byte(nil), field.bytes...)
		case field.num == 2 && field.wire == 2:
			name = string(field.bytes)
		case field.num == 3 && field.wire == 2:
			issuer = string(field.bytes)
		case field.num == 4 && field.wire == 0:
			switch field.varint {
			case 0, 1:
				algorithm = "SHA1"
			case 2:
				algorithm = "SHA256"
			case 3:
				algorithm = "SHA512"
			default:
				return nil, fmt.Errorf("不支持的算法")
			}
		case field.num == 5 && field.wire == 0:
			switch field.varint {
			case 0, 1:
				digits = 6
			case 2:
				digits = 8
			default:
				return nil, fmt.Errorf("位数只支持 6 或 8")
			}
		case field.num == 6 && field.wire == 0:
			otpType = int(field.varint)
		case field.num == 7 && field.wire == 0:
			counter = field.varint
		}
	}
	if otpType == 1 || (otpType == 0 && counter > 0) {
		return nil, fmt.Errorf("仅支持 totp 类型")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("URI 中缺少密钥")
	}
	accountName := strings.TrimSpace(name)
	if issuer == "" {
		if index := strings.Index(accountName, ":"); index >= 0 {
			issuer = strings.TrimSpace(accountName[:index])
			accountName = strings.TrimSpace(accountName[index+1:])
		}
	} else if index := strings.Index(accountName, ":"); index >= 0 {
		accountName = strings.TrimSpace(accountName[index+1:])
	}
	digits, err = normalizeDigits(digits)
	if err != nil {
		return nil, err
	}
	return &parsedOtpauth{
		Issuer:    strings.TrimSpace(issuer),
		Account:   accountName,
		Secret:    encodeBase32Secret(secret),
		Algorithm: algorithm,
		Digits:    digits,
		Period:    defaultPeriod,
	}, nil
}

type protoField struct {
	num    int
	wire   int
	varint uint64
	bytes  []byte
}

func readProtoFields(data []byte) ([]protoField, error) {
	var fields []protoField
	index := 0
	for index < len(data) {
		key, next, err := readProtoVarint(data, index)
		if err != nil {
			return nil, err
		}
		index = next
		field := protoField{
			num:  int(key >> 3),
			wire: int(key & 7),
		}
		switch field.wire {
		case 0:
			value, next, err := readProtoVarint(data, index)
			if err != nil {
				return nil, err
			}
			field.varint = value
			index = next
		case 1:
			if index+8 > len(data) {
				return nil, fmt.Errorf("protobuf 截断")
			}
			index += 8
		case 2:
			length, next, err := readProtoVarint(data, index)
			if err != nil {
				return nil, err
			}
			index = next
			if length > uint64(len(data)-index) {
				return nil, fmt.Errorf("protobuf 截断")
			}
			field.bytes = data[index : index+int(length)]
			index += int(length)
		case 5:
			if index+4 > len(data) {
				return nil, fmt.Errorf("protobuf 截断")
			}
			index += 4
		default:
			return nil, fmt.Errorf("不支持的 protobuf 字段")
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func readProtoVarint(data []byte, index int) (uint64, int, error) {
	var value uint64
	var shift uint
	start := index
	for index < len(data) {
		item := data[index]
		index++
		value |= uint64(item&0x7f) << shift
		if item < 0x80 {
			return value, index, nil
		}
		shift += 7
		if shift > 63 {
			return 0, start, fmt.Errorf("protobuf varint 过长")
		}
	}
	return 0, start, fmt.Errorf("protobuf 截断")
}
