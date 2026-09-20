package main

import (
	"encoding/base64"
	"testing"
)

func TestParseImportGoogleMigration(t *testing.T) {
	secret, err := decodeBase32Secret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	first := encodeMigrationAccount(secret, "alice@google.com", "Example", 1, 1, 2)
	secondSecret, err := decodeBase32Secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	second := encodeMigrationAccount(secondSecret, "bob", "GitHub", 2, 2, 2)
	payload := appendBytesField(nil, 1, first)
	payload = appendBytesField(payload, 1, second)
	uri := "otpauth-migration://offline?data=" + base64.RawURLEncoding.EncodeToString(payload)

	accounts, err := parseImportText(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatalf("got %d accounts: %+v", len(accounts), accounts)
	}
	if accounts[0].Issuer != "Example" || accounts[0].Account != "alice@google.com" {
		t.Fatalf("first %+v", accounts[0])
	}
	if accounts[0].Algorithm != "SHA1" || accounts[0].Digits != 6 || accounts[0].Period != 30 {
		t.Fatalf("first options %+v", accounts[0])
	}
	if _, err := decodeBase32Secret(accounts[0].Secret); err != nil {
		t.Fatal(err)
	}
	if accounts[1].Issuer != "GitHub" || accounts[1].Algorithm != "SHA256" || accounts[1].Digits != 8 {
		t.Fatalf("second %+v", accounts[1])
	}
}

func TestParseImportSkipsHotpInMigration(t *testing.T) {
	secret, err := decodeBase32Secret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	hotp := encodeMigrationAccount(secret, "alice", "Example", 1, 1, 1)
	totp := encodeMigrationAccount(secret, "bob", "Example", 1, 1, 2)
	payload := appendBytesField(nil, 1, hotp)
	payload = appendBytesField(payload, 1, totp)
	uri := "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString(payload)
	accounts, err := parseImportText(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Account != "bob" {
		t.Fatalf("got %+v", accounts)
	}
}

func TestParseImportJSONFormats(t *testing.T) {
	aegis := `{
		"version": 1,
		"header": {"slots": null, "params": null},
		"db": {
			"entries": [{
				"type": "totp",
				"name": "alice",
				"issuer": "GitHub",
				"info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "period": 60}
			}]
		}
	}`
	accounts, err := parseImportText(aegis)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Issuer != "GitHub" || accounts[0].Account != "alice" || accounts[0].Algorithm != "SHA256" || accounts[0].Digits != 8 || accounts[0].Period != 60 {
		t.Fatalf("%+v", accounts[0])
	}

	andotp := `[{"secret":"JBSWY3DPEHPK3PXP","label":"GitHub - alice","issuer":"GitHub","digits":6,"type":"TOTP","algorithm":"SHA1","period":30}]`
	accounts, err = parseImportText(andotp)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Account != "alice" {
		t.Fatalf("%+v", accounts)
	}

	twofas := `{"services":[{"name":"GitHub","otp":{"account":"alice","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30,"tokenType":"TOTP"}}]}`
	accounts, err = parseImportText(twofas)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Issuer != "GitHub" || accounts[0].Account != "alice" {
		t.Fatalf("%+v", accounts)
	}

	freeotp := `{"tokens":[{"type":"TOTP","algo":"SHA1","digits":6,"period":30,"issuerExt":"Example","label":"alice","secret":[72,101,108,108,111,33]}]}`
	accounts, err = parseImportText(freeotp)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Issuer != "Example" {
		t.Fatalf("%+v", accounts)
	}
	if _, err := decodeBase32Secret(accounts[0].Secret); err != nil {
		t.Fatal(err)
	}

	bitwarden := `{"items":[{"login":{"totp":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"}}]}`
	accounts, err = parseImportText(bitwarden)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Account != "alice" {
		t.Fatalf("%+v", accounts)
	}
}

func TestParseImportEncryptedAegisRejected(t *testing.T) {
	raw := `{"version":1,"header":{"slots":[{"key":"x"}],"params":{}},"db":"ciphertext"}`
	if _, err := parseImportText(raw); err == nil {
		t.Fatal("expected encrypted aegis rejection")
	}
}

func TestParseImportAliasesAndBareSecret(t *testing.T) {
	parsed, err := parseOtpauthURI("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-1&interval=30")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Algorithm != "SHA1" || parsed.Period != 30 {
		t.Fatalf("%+v", parsed)
	}

	hexURI := "otpauth://totp/Example:alice?secret=48656c6c6f21&encoding=hex&issuer=Example"
	parsed, err = parseOtpauthURI(hexURI)
	if err != nil {
		t.Fatal(err)
	}
	key, err := decodeBase32Secret(parsed.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "Hello!" {
		t.Fatalf("hex secret mismatch %q", key)
	}

	accounts, err := parseImportText("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%+v", accounts)
	}

	accounts, err = parseImportText("GitHub:alice\nJBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if accounts[0].Issuer != "GitHub" || accounts[0].Account != "alice" {
		t.Fatalf("%+v", accounts[0])
	}

	text := "otpauth://totp/One:a?secret=JBSWY3DPEHPK3PXP\notpauth://totp/Two:b?secret=JBSWY3DPEHPK3PXP"
	accounts, err = parseImportText(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatalf("got %d", len(accounts))
	}
}

func TestParseImportSteamRejected(t *testing.T) {
	if _, err := parseOtpauthURI("otpauth://steam/Steam:user?secret=JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("expected steam rejection")
	}
}

func TestImportGoogleMigrationAddsAllAccounts(t *testing.T) {
	secret, err := decodeBase32Secret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	first := encodeMigrationAccount(secret, "alice", "One", 1, 1, 2)
	second := encodeMigrationAccount(secret, "bob", "Two", 1, 1, 2)
	payload := appendBytesField(nil, 1, first)
	payload = appendBytesField(payload, 1, second)
	uri := "otpauth-migration://offline?data=" + base64.RawURLEncoding.EncodeToString(payload)
	p := newPluginWithPath(t.TempDir() + "/vault.bin")
	result, pluginErr := p.importAccounts(map[string]any{"text": uri})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	payloadMap := result.(map[string]any)
	if payloadMap["success"] != true || payloadMap["imported"] != 2 {
		t.Fatalf("%+v", payloadMap)
	}
	current, pluginErr := p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	accounts := current.(map[string]any)["accounts"].([]any)
	if len(accounts) != 2 {
		t.Fatalf("got %d", len(accounts))
	}
	if accounts[0].(map[string]any)["account"] != "alice" || accounts[1].(map[string]any)["account"] != "bob" {
		t.Fatalf("%+v", accounts)
	}
}

func encodeMigrationAccount(secret []byte, name, issuer string, algorithm, digits, otpType uint64) []byte {
	payload := appendBytesField(nil, 1, secret)
	payload = appendBytesField(payload, 2, []byte(name))
	payload = appendBytesField(payload, 3, []byte(issuer))
	payload = appendVarintField(payload, 4, algorithm)
	payload = appendVarintField(payload, 5, digits)
	payload = appendVarintField(payload, 6, otpType)
	return payload
}

func appendVarint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

func appendBytesField(dst []byte, field int, data []byte) []byte {
	dst = appendVarint(dst, uint64(field<<3|2))
	dst = appendVarint(dst, uint64(len(data)))
	return append(dst, data...)
}

func appendVarintField(dst []byte, field int, value uint64) []byte {
	dst = appendVarint(dst, uint64(field<<3))
	return appendVarint(dst, value)
}
