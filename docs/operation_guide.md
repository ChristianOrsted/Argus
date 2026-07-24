# Argus 操作指导

更新日期：2026-07-16

## 1. 当前前后端端口说明

当前项目不是前端 dev server + 后端 API server 的双进程架构，而是一个 Python Dashboard 进程同时承载：

- 前端页面：`dashboard/index.html`、`dashboard/app.js`、`dashboard/styles.css`
- 后端 API：`/api/summary`、`/api/deepseek-redteam-batch`、`/api/analyze-miss` 等

默认访问地址：

```text
http://127.0.0.1:8765
```

所以“开启前端”和“开启后端”在当前版本里是同一个动作：启动 `scripts/dashboard_server.py`。关闭端口也是关闭这个 Python 进程。

## 2. 启动 Dashboard

在 PowerShell 中进入项目目录：

```powershell
cd E:\eve_jump\暑期课程\Argus
```

如果虚拟环境尚未激活：

```powershell
.\.venv\Scripts\Activate.ps1
```

启动默认端口：

```powershell
.\.venv\Scripts\python scripts\dashboard_server.py --host 127.0.0.1 --port 8765
```

浏览器打开：

```text
http://127.0.0.1:8765
```

如果要临时换端口，例如 8766：

```powershell
.\.venv\Scripts\python scripts\dashboard_server.py --host 127.0.0.1 --port 8766
```

对应浏览器地址改为：

```text
http://127.0.0.1:8766
```

## 3. 检查端口是否启动成功

检查页面是否返回 200：

```powershell
(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8765/).StatusCode
```

检查后端 API 是否可用：

```powershell
(Invoke-RestMethod http://127.0.0.1:8765/api/summary).summary
```

查看 8765 端口监听进程：

```powershell
Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
```

## 4. 关闭 Dashboard

如果 Dashboard 是在当前 PowerShell 窗口前台运行的，直接按：

```text
Ctrl + C
```

如果要按端口强制关闭 8765 上的 Dashboard 进程：

```powershell
$listenPids = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty OwningProcess -Unique

foreach ($listenPid in $listenPids) {
  Stop-Process -Id $listenPid -Force
}
```

如果 `Get-NetTCPConnection` 不可用，可以使用 `netstat` 版本：

```powershell
$listenPids = netstat -ano |
  Select-String ':8765' |
  ForEach-Object { ($_ -split '\s+')[-1] } |
  Where-Object { $_ -match '^\d+$' -and $_ -ne '0' } |
  Select-Object -Unique

foreach ($listenPid in $listenPids) {
  Stop-Process -Id ([int]$listenPid) -Force
}
```

关闭后再检查一次：

```powershell
Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
```

没有输出就表示端口已经释放。

## 5. DeepSeek API 使用方式

推荐演示时在网页输入框临时填入 DeepSeek API Key。该 key 只会随本次本地请求发送到 `dashboard_server.py`，不会被前端保存，也不应该写入脚本、文档或提交。

也可以在当前 PowerShell 会话中临时设置环境变量：

```powershell
$env:DEEPSEEK_API_KEY = "你的临时 key"
.\.venv\Scripts\python scripts\dashboard_server.py --host 127.0.0.1 --port 8765
```

注意：不要把真实 key 写入 `.env` 后提交，也不要写入任何文档或脚本。

## 6. DeepSeek 网络错误排查

如果网页端出现：

```text
WinError 10013
```

通常不是 API Key 错误，而是启动 Dashboard 的 Python 进程没有出站网络权限。处理方式：

1. 关闭当前 8765 端口上的 Dashboard 进程。
2. 从有网络权限的终端重新启动 `dashboard_server.py`。
3. 如果仍失败，检查 Windows 防火墙、安全软件或代理设置，允许 Python 访问：

```text
https://api.deepseek.com
```

可以先用不启用 intent judge 的 DeepSeek 红队生成测试连通性；连通后再勾选“同时启用 DeepSeek intent judge”。

## 7. 推荐演示流程

1. 启动 Dashboard。
2. 打开 `http://127.0.0.1:8765`。
3. 点击某个攻击面的“离线重跑”，确认四层 Guardian 能显示 Verdict。
4. 在 DeepSeek Red Team 区域选择攻击面，例如“模型越狱”或“工具调用劫持”。
5. 设置生成条数，例如 3。
6. 检查红队提示词是否与当前攻击面一致，必要时手动修改。
7. 输入临时 DeepSeek API Key。
8. 点击“运行 DeepSeek 红队”。
9. 查看批量矩阵中的“总 / 1 / 2 / 3 / 4”状态。
10. 点击某个条目查看 DeepSeek 原始攻击 JSON 和 Guardian 审计细节。
11. 如果出现漏拦截，点击“分析漏拦截”，观察自适应规则和重评估结果。

## 8. 常用验收命令

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m compileall src scripts tests
.\.venv\Scripts\python scripts\run_benchmark.py
node --check dashboard\app.js
```

当前网页端口验收：

```powershell
(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8765/).StatusCode
(Invoke-RestMethod http://127.0.0.1:8765/api/summary).summary.detected
```
