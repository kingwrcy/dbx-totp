# TOTP

DBX 插件：由 Go Sidecar 在本地保存 TOTP 账号并生成动态验证码。不需要新建数据库连接。

需要 DBX **0.6.21 或更高版本**。安装后点击全局工具栏的蓝色盾牌时钟图标，在底部 Dock 中打开「TOTP 验证器」。也可以从命令面板搜索 `TOTP` 打开，或从插件中心进入「验证器」工作台。

密钥保存在本机仓库（Windows 使用 DPAPI 加密），工作台只拿到验证码，不会返回密钥。

## 功能

- 全局工具栏入口、底部 Dock 横向紧凑账号行和命令面板入口
- 命令面板重复打开时聚焦已有 TOTP 面板，插件中心保留独立工作台入口
- 一次导入多个 TOTP 账号（Google 导出码、otpauth URI、未加密备份 JSON）
- 支持 SHA1 / SHA256 / SHA512、6 或 8 位、自定义周期
- 列表显示当前验证码、倒计时、复制和删除

仓库默认路径：`%AppData%\dbx-totp\vault.bin`。测试可用环境变量 `DBX_TOTP_VAULT` 覆盖。

### Dock 使用说明

- Dock 中支持查看、复制、导入和管理账号，面板高度可通过 DBX 拖动调整。
- 宽面板中每个账号横向显示签发方／账号、验证码、倒计时和操作按钮；较窄面板自动换行，小窗口回退为纵向卡片。
- DBX 0.6.21 的工具栏按钮统一切换整个 Dock 的显示状态。如果 Dock 已有其他插件面板，请从命令面板执行「TOTP 验证器」，准确打开或聚焦 TOTP。
- 入口使用 Manifest 的 `command` / `menus` 贡献点，声明 `appToolbar`、`commandPalette` 和 `presentation: "panel"`。DBX 官方 JSON Schema 暂未同步这些字段，配置依据为 v0.6.21 的运行时实现。

## 开发

需要 Node.js 22+、Go 1.22+ 和 DBX Plugin CLI 0.1.9（已验证支持命令与菜单贡献点）：

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
