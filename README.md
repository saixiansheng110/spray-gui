# spray + Web GUI

Spray 是 [chainreactors/spray](https://github.com/chainreactors/spray) 的 Go 实现,这是一款高性能 HTTP 目录/路径爆破与信息收集工具。本仓库在原生 spray 基础上增加了 **Web 图形界面**(浏览器端配置 + 实时结果展示),整合了 OneScan 的内网 IP 绕过思路与可自定义 UA 池。

## 主要改动(相对于上游 spray)

### webgui(浏览器图形界面)
- `web/main.go` + `web/static/index.html` — Go 标准库 HTTP 服务 + SSE 实时结果推送
- 表单:目标输入、字典/规则/URL 文件上传、掩码、插件、过滤/匹配表达式、请求/性能调优、结果导出 CSV
- 实时结果表:状态码、长度、耗时、URL、标题、指纹、来源
- 内置使用教程(折叠面板)、结果计数、清空
- 端口:默认 888,8080 被硬禁止(留给 Burp)

### spray 内核改动
- 内网 IP 绕过 (`--random-local-ip`):每请求注入 4 个 SSRF 绕过头,每个用不同私网段(127.0.0.1 / 10.x / 172.x / 192.168.x)
- User-Agent 轮换:`httputils.RandomUA` 被加载自仓库内的 `web/UA.txt`(22 个现代 UA),`--random-agent` 时真正轮换
- 修复 spray 自身 bug:`core/runner.go` 中 `RandomUserAgent==true` 时不再设默认 UA,避免随机 UA 被覆盖

### 新增文件
- `web/` — Web GUI 后端 + 前端(单文件 HTML)+ UA.txt
- `web/uploads/` — 用户上传字典、URL 列表文件的存储目录
- `rule/` — 5 个常用 hashcat 规则文件(basic / common / cases / backup / extensions)
- `dictionary/` — 测试用字典合集(33 个)
- `dictionary/spring-merged.txt` — spring 系列 3 个字典去重合并产物

## 快速开始

### 1. 编译 spray CLI(可选)
```bash
go build -o spray .
```

### 2. 编译并运行 Web GUI
```bash
cd web
go build -o spray-webgui .
./spray-webgui          # 默认端口 888
```
打开 http://localhost:888,点顶部「使用教程」看详细说明。

## 使用教程(简版)

### check 模式(类似 httpx)
只填目标 URL,字典留空。自动对每个目标发请求、收指纹、提取敏感信息。

### brute 模式(类似 dirsearch)
1. 上传字典(左侧「字典文件」→「选择并上传字典」)
2. 可选:填扩展名(`php,asp`)、掩码(`{?l#4}`)、规则文件(右侧「规则文件」)
3. 可选:勾选插件(-a 一键全开,或单独选指纹/备份/爬虫等)
5. 点「开始扫描」

### 过滤与判定
- 状态码:默认 200 白、400/410 黑
- 匹配表达式:如 `current.Status != 200` 保留非 200
- 过滤表达式:如 `current.Body contains "powered by"` 过滤掉包含某内容的响应
- 模糊输出(fuzzy):基于 simhash 相似度去重
- 去重(unique):对 403/200/404 去重

### 走 Burp 代理
填代理 `http://127.0.0.1:8080/`,会自动切到 `req` client 绕过 spray 默认 fast client 与 Burp 不兼容的问题。**注意关闭 Burp 的 Intercept 开关**,否则请求会被卡住。

## 文件结构

```
.
├── README.md
├── LICENSE                          (上游 Apache 2.0)
├── spray.go / core/ / cmd/ / pkg/   (上游 spray 源码)
├── web/                             (Web GUI,核心新代码)
│   ├── main.go
│   ├── static/index.html
│   ├── UA.txt                       (用户自定义 UA 池)
│   ├── go.mod / go.sum
│   └── uploads/                     (运行时上传字典的目录)
├── rule/                            (常用 hashcat 规则)
│   ├── basic.txt
│   ├── common.txt
│   ├── cases.txt
│   ├── backup.txt
│   └── extensions.txt
├── dictionary/                       (测试用字典合集)
│   └── spring-merged.txt            (合并去重产物)
└── templates/                        (上游 spray 模板,空)
```

## 致谢

- [chainreactors/spray](https://github.com/chainreactors/spray) — 原始 spray 实现(Apache 2.0)
- [vaycore/OneScan](https://github.com/vaycore/OneScan) — 内网 IP 绕过思路参考
- 用户 saixiansheng110 — 本仓库维护者,GUI 设计与功能定制