package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

type plugin struct {
	mutex sync.Mutex
	path  string
	items []*account
}

func newPluginWithPath(path string) *plugin {
	p := &plugin{path: path}
	_ = p.load()
	return p
}

func (p *plugin) Handle(
	_ dbxpluginsdk.RequestContext,
	method string,
	params json.RawMessage,
	_ *dbxpluginsdk.Emitter,
) (any, *dbxpluginsdk.PluginError) {
	values, err := parseParams(params)
	if err != nil {
		return nil, invalidParams("请求参数无效")
	}
	switch method {
	case "totp/current":
		return p.current()
	case "totp/import":
		return p.importAccounts(values)
	case "totp/update":
		return p.updateAccount(values)
	case "totp/export":
		return p.exportAccounts(values)
	case "totp/remove":
		return p.removeAccount(values)
	default:
		return nil, dbxpluginsdk.MethodNotFound(method)
	}
}

func (p *plugin) current() (any, *dbxpluginsdk.PluginError) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := time.Now()
	accounts := make([]any, 0, len(p.items))
	for _, item := range p.items {
		payload, err := item.publicCode(now)
		if err != nil {
			return nil, invalidParams(err.Error())
		}
		accounts = append(accounts, payload)
	}
	return map[string]any{"accounts": accounts}, nil
}

func (p *plugin) importAccounts(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	text := firstString(values, "text", "otpauth_uri", "otpauthUri")
	parsed, err := parseImportText(text)
	if err != nil {
		return nil, invalidParams(err.Error())
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	seen := map[string]struct{}{}
	for _, item := range p.items {
		seen[item.fingerprint()] = struct{}{}
	}

	imported := 0
	skipped := 0
	for _, item := range parsed {
		account, convErr := accountFromParsed(item, "")
		if convErr != nil {
			skipped++
			continue
		}
		fp := account.fingerprint()
		if _, exists := seen[fp]; exists {
			account.wipe()
			skipped++
			continue
		}
		seen[fp] = struct{}{}
		p.items = append(p.items, account)
		imported++
	}
	if imported == 0 && skipped == 0 {
		return map[string]any{
			"success":  false,
			"imported": 0,
			"skipped":  0,
			"total":    len(p.items),
			"message":  "未找到可用的 TOTP 账号",
		}, nil
	}
	if err := p.saveLocked(); err != nil {
		return nil, invalidParams(err.Error())
	}
	message := fmt.Sprintf("已导入 %d 个账号。", imported)
	if skipped > 0 {
		message = fmt.Sprintf("已导入 %d 个账号，跳过 %d 个重复或无效项。", imported, skipped)
	}
	return map[string]any{
		"success":  imported > 0,
		"imported": imported,
		"skipped":  skipped,
		"total":    len(p.items),
		"message":  message,
	}, nil
}

func (p *plugin) updateAccount(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	id := firstString(values, "id")
	if id == "" {
		return nil, invalidParams("缺少账号 ID")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	item := p.findLocked(id)
	if item == nil {
		return nil, invalidParams("账号不存在")
	}

	issuer := firstString(values, "issuer")
	accountName := firstString(values, "account")
	algorithm := item.Algorithm
	if raw := firstString(values, "algorithm"); raw != "" {
		normalized, err := normalizeAlgorithm(raw)
		if err != nil {
			return nil, invalidParams(err.Error())
		}
		algorithm = normalized
	}
	digits := item.Digits
	if _, ok := values["digits"]; ok && stringify(values["digits"]) != "" {
		parsed, err := toInt(values["digits"])
		if err != nil {
			return nil, invalidParams("位数无效")
		}
		normalized, err := normalizeDigits(parsed)
		if err != nil {
			return nil, invalidParams(err.Error())
		}
		digits = normalized
	}
	period := item.Period
	if _, ok := values["period"]; ok && stringify(values["period"]) != "" {
		parsed, err := toInt(values["period"])
		if err != nil {
			return nil, invalidParams("周期无效")
		}
		normalized, err := normalizePeriod(parsed)
		if err != nil {
			return nil, invalidParams(err.Error())
		}
		period = normalized
	}
	secret := item.Secret
	if raw := firstString(values, "secret"); raw != "" {
		key, err := decodeBase32Secret(raw)
		if err != nil {
			return nil, invalidParams(err.Error())
		}
		secret = key
	}

	updated := &account{
		ID:        item.ID,
		Issuer:    issuer,
		Account:   accountName,
		Name:      displayNameFrom(issuer, accountName),
		Secret:    secret,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}
	fp := updated.fingerprint()
	for _, other := range p.items {
		if other.ID != item.ID && other.fingerprint() == fp {
			if raw := firstString(values, "secret"); raw != "" {
				for i := range secret {
					secret[i] = 0
				}
			}
			return nil, invalidParams("已存在相同账号")
		}
	}
	if raw := firstString(values, "secret"); raw != "" {
		item.wipe()
	}
	*item = *updated
	if err := p.saveLocked(); err != nil {
		return nil, invalidParams(err.Error())
	}
	return map[string]any{"success": true, "total": len(p.items)}, nil
}

func (p *plugin) exportAccounts(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	id := firstString(values, "id")
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if id != "" {
		item := p.findLocked(id)
		if item == nil {
			return nil, invalidParams("账号不存在")
		}
		return map[string]any{
			"success": true,
			"count":   1,
			"text":    item.otpauthURI(),
		}, nil
	}
	lines := make([]string, 0, len(p.items))
	for _, item := range p.items {
		lines = append(lines, item.otpauthURI())
	}
	if len(lines) == 0 {
		return map[string]any{
			"success": false,
			"count":   0,
			"text":    "",
			"message": "没有可导出的账号",
		}, nil
	}
	return map[string]any{
		"success": true,
		"count":   len(lines),
		"text":    strings.Join(lines, "\n"),
	}, nil
}

func (p *plugin) findLocked(id string) *account {
	for _, item := range p.items {
		if item.ID == id {
			return item
		}
	}
	return nil
}

func (p *plugin) removeAccount(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	id := firstString(values, "id")
	if id == "" {
		return nil, invalidParams("缺少账号 ID")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	index := -1
	for i, item := range p.items {
		if item.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, invalidParams("账号不存在")
	}
	p.items[index].wipe()
	p.items = append(p.items[:index], p.items[index+1:]...)
	if err := p.saveLocked(); err != nil {
		return nil, invalidParams(err.Error())
	}
	return map[string]any{
		"success": true,
		"total":   len(p.items),
	}, nil
}

func invalidParams(message string) *dbxpluginsdk.PluginError {
	return dbxpluginsdk.NewError(-32602, message)
}

func main() {
	metadata := dbxpluginsdk.Metadata{
		ID:           "io.github.kingwrcy.totp",
		Version:      "0.2.0",
		Capabilities: []string{},
	}
	server := dbxpluginsdk.NewServer(metadata, newPluginWithPath(vaultPath()))
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
