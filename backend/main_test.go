package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

func TestInitializeIdentityMatchesManifest(t *testing.T) {
	data, err := os.ReadFile("../manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}

	request := `{"jsonrpc":"2.0","id":1,"method":"plugin/initialize","params":{"host":{"protocolVersions":[1]}}}`
	var output, errors bytes.Buffer
	server := dbxpluginsdk.NewServer(pluginMetadata(), &plugin{}).WithIO(strings.NewReader(request+"\n"), &output, &errors)
	if err := server.Serve(); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			Plugin struct {
				ID      string `json:"id"`
				Version string `json:"version"`
			} `json:"plugin"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("解析初始化响应失败：%v，输出：%s，错误：%s", err, output.String(), errors.String())
	}
	if response.Result.Plugin.ID != manifest.ID || response.Result.Plugin.Version != manifest.Version {
		t.Fatalf("后端身份 %s/%s 与清单 %s/%s 不一致", response.Result.Plugin.ID, response.Result.Plugin.Version, manifest.ID, manifest.Version)
	}
}
