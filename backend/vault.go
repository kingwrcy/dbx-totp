package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const vaultMagic = "DBXTOTP1"

type vaultDoc struct {
	Version  int           `json:"version"`
	Accounts []vaultRecord `json:"accounts"`
}

type vaultRecord struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

func vaultPath() string {
	if path := strings.TrimSpace(os.Getenv("DBX_TOTP_VAULT")); path != "" {
		return path
	}
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "dbx-totp", "vault.bin")
}

func encodeVault(plain []byte) ([]byte, error) {
	protected, err := protectBytes(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(vaultMagic)+len(protected))
	out = append(out, vaultMagic...)
	return append(out, protected...), nil
}

func decodeVault(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return []byte(`{"version":1,"accounts":[]}`), nil
	}
	if trimmed[0] == '{' {
		return trimmed, nil
	}
	if bytes.HasPrefix(data, []byte(vaultMagic)) {
		return unprotectBytes(data[len(vaultMagic):])
	}
	return unprotectBytes(data)
}

func (p *plugin) load() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			p.replaceItems(nil)
			return nil
		}
		return fmt.Errorf("读取仓库失败")
	}
	plain, err := decodeVault(data)
	if err != nil {
		return fmt.Errorf("解密仓库失败")
	}
	var doc vaultDoc
	if err := json.Unmarshal(plain, &doc); err != nil {
		return fmt.Errorf("仓库损坏")
	}
	items := make([]*account, 0, len(doc.Accounts))
	for _, record := range doc.Accounts {
		item, err := accountFromRecord(record)
		if err != nil {
			continue
		}
		items = append(items, item)
	}
	p.replaceItems(items)
	return nil
}

func (p *plugin) saveLocked() error {
	doc := vaultDoc{Version: 1, Accounts: make([]vaultRecord, 0, len(p.items))}
	for _, item := range p.items {
		doc.Accounts = append(doc.Accounts, vaultRecord{
			ID:        item.ID,
			Issuer:    item.Issuer,
			Account:   item.Account,
			Name:      item.Name,
			Secret:    encodeBase32Secret(item.Secret),
			Algorithm: item.Algorithm,
			Digits:    item.Digits,
			Period:    item.Period,
		})
	}
	plain, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("序列化仓库失败")
	}
	blob, err := encodeVault(plain)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建仓库目录失败")
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("写入仓库失败")
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("保存仓库失败")
	}
	return nil
}

func (p *plugin) replaceItems(items []*account) {
	for _, existing := range p.items {
		existing.wipe()
	}
	p.items = items
}
