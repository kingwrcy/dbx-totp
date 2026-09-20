# TOTP

DBX 插件：由 Go Sidecar 在本地保存 TOTP 账号并生成动态验证码。不需要新建数据库连接。

安装后从插件中心打开「验证器」工作台。不支持从侧边栏打开。

密钥保存在本机仓库（Windows 使用 DPAPI 加密），工作台只拿到验证码，不会返回密钥。

## 功能

- 从插件中心打开「验证器」工作台
- 一次导入多个 TOTP 账号（Google 导出码、otpauth URI、未加密备份 JSON）
- 支持 SHA1 / SHA256 / SHA512、6 或 8 位、自定义周期
- 列表显示当前验证码、倒计时、复制和删除

仓库默认路径：`%AppData%\dbx-totp\vault.bin`。测试可用环境变量 `DBX_TOTP_VAULT` 覆盖。

## 开发

需要 Node.js 22+ 和 Go 1.22+：

```bash
dbx-plugin dev --path . --port 5190
```

后端测试：

```bash
cd backend
go test ./...
```

打包未签名候选包（本机当前平台）：

```bash
dbx-plugin package .
```

Go Sidecar 不能打 `universal` 包。商店需要按平台各打一份：`linux-x64`、`linux-arm64`、`windows-x64`、`darwin-x64`、`darwin-arm64`。发布 GitHub Release 后，`.github/workflows/plugin-release.yml` 会在对应 runner 上设置 `DBX_PLUGIN_TARGET` 并调用 `dbx-plugin package .`。

本地指定平台：

```bash
dbx-plugin package . --target windows-x64
```

本地安装未签名包时，需要在 DBX 插件中心打开“允许安装未签名开发包”。
