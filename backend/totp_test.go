package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateSHA1RFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, item := range cases {
		got, err := generateTOTP(secret, time.Unix(item.unix, 0).UTC(), 30, 8, "SHA1")
		if err != nil {
			t.Fatalf("unix=%d: %v", item.unix, err)
		}
		if got != item.want {
			t.Fatalf("unix=%d got=%s want=%s", item.unix, got, item.want)
		}
	}
}

func TestGenerateSHA256AndSHA512RFC6238(t *testing.T) {
	sha256Secret := []byte("12345678901234567890123456789012")
	sha512Secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	got256, err := generateTOTP(sha256Secret, time.Unix(59, 0).UTC(), 30, 8, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if got256 != "46119246" {
		t.Fatalf("sha256 got=%s", got256)
	}
	got512, err := generateTOTP(sha512Secret, time.Unix(59, 0).UTC(), 30, 8, "SHA512")
	if err != nil {
		t.Fatal(err)
	}
	if got512 != "90693936" {
		t.Fatalf("sha512 got=%s", got512)
	}
}

func TestDecodeBase32Secret(t *testing.T) {
	key, err := decodeBase32Secret("JBSWY3DPEE")
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "Hello!" {
		t.Fatalf("got=%q", key)
	}
	if _, err := decodeBase32Secret("JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBase32Secret("%%%"); err == nil {
		t.Fatal("expected invalid secret")
	}
}

func TestRemainingSeconds(t *testing.T) {
	if got := remainingSeconds(time.Unix(29, 0), 30); got != 1 {
		t.Fatalf("got=%d", got)
	}
	if got := remainingSeconds(time.Unix(30, 0), 30); got != 30 {
		t.Fatalf("got=%d", got)
	}
}

func TestParseOtpauthURI(t *testing.T) {
	parsed, err := parseOtpauthURI("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Issuer != "Example" || parsed.Account != "alice@google.com" {
		t.Fatalf("label mismatch: %+v", parsed)
	}
	if parsed.Algorithm != "SHA256" || parsed.Digits != 8 || parsed.Period != 60 {
		t.Fatalf("options mismatch: %+v", parsed)
	}
	if _, err := parseOtpauthURI("otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("expected hotp rejection")
	}
}

func TestImportAddsAllAndOmitsSecret(t *testing.T) {
	p := newPluginWithPath(t.TempDir() + "/vault.bin")
	text := "otpauth://totp/One:a?secret=JBSWY3DPEHPK3PXP\notpauth://totp/Two:b?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	result, pluginErr := p.importAccounts(map[string]any{"text": text})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	payload := result.(map[string]any)
	if payload["success"] != true || payload["imported"] != 2 {
		t.Fatalf("%+v", payload)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(encoded)), "JBSWY3DPEHPK3PXP") {
		t.Fatal("secret leaked from import")
	}

	current, pluginErr := p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	encoded, err = json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(encoded)), "JBSWY3DPEHPK3PXP") {
		t.Fatal("secret leaked from current")
	}
	accounts := current.(map[string]any)["accounts"].([]any)
	if len(accounts) != 2 {
		t.Fatalf("got %d accounts", len(accounts))
	}
	first := accounts[0].(map[string]any)
	if first["issuer"] != "One" || first["account"] != "a" || first["code"] == "" || first["secret"] != nil {
		t.Fatalf("%+v", first)
	}
}

func TestImportSkipsDuplicatesAndRemove(t *testing.T) {
	p := newPluginWithPath(t.TempDir() + "/vault.bin")
	uri := "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	if _, err := p.importAccounts(map[string]any{"text": uri}); err != nil {
		t.Fatal(err)
	}
	again, err := p.importAccounts(map[string]any{"text": uri})
	if err != nil {
		t.Fatal(err)
	}
	payload := again.(map[string]any)
	if payload["imported"] != 0 || payload["skipped"] != 1 || payload["total"] != 1 {
		t.Fatalf("%+v", payload)
	}
	current, pluginErr := p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	id := current.(map[string]any)["accounts"].([]any)[0].(map[string]any)["id"].(string)
	if _, err := p.removeAccount(map[string]any{"id": id}); err != nil {
		t.Fatal(err)
	}
	current, pluginErr = p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	accounts := current.(map[string]any)["accounts"].([]any)
	if len(accounts) != 0 {
		t.Fatalf("got %d", len(accounts))
	}
}

func TestUpdateAccountKeepsSecretAndRejectsDuplicate(t *testing.T) {
	p := newPluginWithPath(t.TempDir() + "/vault.bin")
	if _, err := p.importAccounts(map[string]any{
		"text": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\notpauth://totp/GitLab:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitLab",
	}); err != nil {
		t.Fatal(err)
	}
	current, pluginErr := p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	id := current.(map[string]any)["accounts"].([]any)[0].(map[string]any)["id"].(string)
	updated, pluginErr := p.updateAccount(map[string]any{
		"id":        id,
		"issuer":    "GitHub",
		"account":   "alice@work",
		"algorithm": "SHA1",
		"digits":    6,
		"period":    30,
	})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	if updated.(map[string]any)["success"] != true {
		t.Fatalf("%+v", updated)
	}
	current, pluginErr = p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	first := current.(map[string]any)["accounts"].([]any)[0].(map[string]any)
	if first["account"] != "alice@work" {
		t.Fatalf("%+v", first)
	}
	exported, pluginErr := p.exportAccounts(map[string]any{"id": id})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	text := exported.(map[string]any)["text"].(string)
	if !strings.Contains(text, "secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("expected original secret in export: %s", text)
	}
	if _, err := p.updateAccount(map[string]any{
		"id":        id,
		"issuer":    "GitLab",
		"account":   "bob",
		"algorithm": "SHA1",
		"digits":    6,
		"period":    30,
		"secret":    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	}); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestExportAllAndCurrentOmitsSecret(t *testing.T) {
	p := newPluginWithPath(t.TempDir() + "/vault.bin")
	if _, err := p.importAccounts(map[string]any{
		"text": "otpauth://totp/One:a?secret=JBSWY3DPEHPK3PXP\notpauth://totp/Two:b?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	}); err != nil {
		t.Fatal(err)
	}
	exported, pluginErr := p.exportAccounts(map[string]any{})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	payload := exported.(map[string]any)
	if payload["success"] != true || payload["count"] != 2 {
		t.Fatalf("%+v", payload)
	}
	text := payload["text"].(string)
	if !strings.Contains(text, "otpauth://totp/") || !strings.Contains(text, "secret=") {
		t.Fatalf("%s", text)
	}
	current, pluginErr := p.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(encoded)), "JBSWY3DPEHPK3PXP") {
		t.Fatal("secret leaked from current")
	}
}

func TestVaultReload(t *testing.T) {
	path := t.TempDir() + "/vault.bin"
	p := newPluginWithPath(path)
	if _, err := p.importAccounts(map[string]any{
		"text": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := newPluginWithPath(path)
	current, pluginErr := reloaded.current()
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	accounts := current.(map[string]any)["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("got %d", len(accounts))
	}
	item := accounts[0].(map[string]any)
	if item["issuer"] != "GitHub" || item["account"] != "alice" {
		t.Fatalf("%+v", item)
	}
}
