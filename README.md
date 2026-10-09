# 移动云电脑 · 服务器版保活面板

协议登录 + 多账号 + 名下全部云电脑保活，**零第三方依赖**，可直接部署到服务器。

```
cmcc_server/
├── cmcc_api.py    # 协议客户端（签名 / RSA 加密 / 登录 / 心跳 / 唤醒）
├── server.py      # 保活引擎 + Web 面板服务 + HTTP API
├── panel.html     # 面板前端（单文件原生 JS，无 CDN）
├── qr.py          # 二维码生成（扫码登录用；编码核心为 qrcodegen.py，MIT）
├── qrcodegen.py   # Nayuki QR-Code-generator 单文件库（MIT，纯标准库）
├── check.py       # 部署自检脚本：联网/代理/证书/时间/端口 一键排查
├── deploy.sh      # Linux 一键部署（systemd，部署前自动自检）
├── start.bat      # Windows 本地启动
├── Dockerfile     # Docker 部署（启动前自动自检）
└── data/          # 账号数据（自动生成 accounts.json）
```

> ⚠️ 部署到新服务器时**整个目录一起拷**（8 个文件缺一不可，尤其 `qr.py` 和 `check.py`）。

---

## 一、它是怎么保活的（v2：SCG 真保活）

> **关键认知**：云电脑的"自动关机计时器"按**桌面连接活动**重置，不是按心跳 API 重置。
> 旧版只发 firm_auth/heartbeat 属于控制面请求，机器照样到点关机（用户实测踩坑）。

现在的保活链路（SCG/深信服线路，协议取自 [1936-zero/cmcc-cloud-alive](https://github.com/1936-zero/cmcc-cloud-alive)，MIT）：

1. **真开机**：检测到关机 → `firm_auth`（新 scAuthCode）→ CEM `getConnectInfo`（`api.soho.komect.com:1443`）
   → 触发 SCG VM 开机（实测 10 秒变运行中）→ 未就绪则轮询 `getVmReadyStatus`
2. **真保活**：每 N 分钟一次 `firm_auth`（新码）→ `getConnectInfo` → **SPICE 长会话（默认 120 秒）**，
   真正建立桌面级连接重置空闲计时器
3. 心跳/上报/登录态校验继续保留（会话健康度观测）

注意：`scAuthCode` 是**一次性**的，每次开机/保活都必须先重新 `firm_auth` 取新码。

**SPICE 长会话为可选增强**：检测 `/opt/cmcc-alive`（或环境变量 `CMCC_ALIVE_PATH`）下的
[cmcc-cloud-alive](https://github.com/1936-zero/cmcc-cloud-alive) 包，找到则用完整 SPICE 会话；
找不到自动降级为"每次保活触发一次 getConnectInfo"（仍是连接事件），面板徽标会显示当前模式：
`SCG·SPICE` / `SCG·连接` / `控制面(弱)`。

面板每个账号有：**⏻ 立即开机**（对已关机设备走 CEM 开机链）和 **⚡ 立即保活一次**（立刻跑一轮 SCG 会话）。

## 一(旧)、控制面链路

逆向官方客户端（`CMCC-JTYDN.exe` / `app.asar`）后，把客户端挂在后台时发的三类请求搬到服务器上跑：

| 信号 | 接口 | 频率 | 作用 |
|---|---|---|---|
| 云电脑心跳 | `POST /terminal/cc/cloudPc/heartbeat/v2` `{userServiceId}` | 30 秒 | 让平台认为云电脑"正在被使用" |
| 设备在线上报 | `POST /terminal/cc/cloudPc/infoReport/v2` | 2 分钟 | 让平台认为有设备在线 |
| 登录态校验 | `POST /terminal/token/checkToken/v1` | 2 小时 | 保持会话有效 |
| **定时保活** | `POST /terminal/cc/getFirmAuth/v1` | **自定义（默认 6 小时）** | **在平台 24h 计时器到期前主动"用一次"，重置计时器** |
| 关机自动唤醒 | `POST /terminal/cc/getFirmAuth/v1` | 检测到关机时 | 兜底：万一还是被关了，自动开机 |

**核心是"定时保活"**：不是等云电脑关机了再开机，而是每 N 分钟（默认 360，可在面板每账号调整，0-1440）主动调一次连接凭证接口，相当于"用了一次云电脑"，把平台的闲置/时长计时器提前重置——让它永远走不到 24 小时关机那一步。面板设备行会显示"上次保活时间 + 下次倒计时"。

所有请求均通过客户端同样的签名（HMAC-SHA256）+ 请求体加密（RSA_NO_PADDING 分块）链路发出，指纹（deviceId/appType）可每个账号独立。

---

## 二、部署到服务器（推荐）

### 部署前/后：一键自检（换服务器必跑）

```bash
python3 check.py --port 8765
```

会逐项检查并给出修复建议：

| 检查项 | 不通过时的处理 |
|---|---|
| Python ≥ 3.9 | 升级 Python |
| 程序文件完整性 | 整个目录重新拷贝（别漏 `qr.py`/`check.py`） |
| data 目录可写 | 检查目录权限 / 用 root 跑 |
| 二维码生成器 | 纯本地算法，不该失败；失败即文件损坏 |
| **官方服务器 · 直连** | 检查 DNS / 出网 / 安全组；程序会自动尝试代理 |
| **官方服务器 · 系统代理** | 仅当检测到代理变量时才测 |
| DNS 解析 | `cat /etc/resolv.conf`，换个 DNS（如 223.5.5.5） |
| SSL 证书验证 | `apt install -y ca-certificates && update-ca-certificates`；应急 `CMCC_INSECURE=1` |
| **系统时间偏差** | 签名带时间戳，偏差过大会被服务端拒绝 → `ntpdate -u pool.ntp.org` |
| 端口可绑定 | 换端口 `--port 8766` |

### 常见环境问题与开关

| 环境变量 | 作用 | 什么时候用 |
|---|---|---|
| `CMCC_PORT=8765` | 服务端口 | 默认 8765；云服务器只放行 80 时用 `CMCC_PORT=80` |
| `CMCC_PANEL_PASS=xxx` | 面板访问密码 | 公网部署必须设 |
| `CMCC_USE_PROXY=1` | 强制优先走系统代理 | 你的网络**必须**走代理才能出网 |
| `CMCC_INSECURE=1` | 跳过 SSL 证书校验 | 老系统 CA 过旧报 `certificate verify failed` 时应急 |

### 方式 A：一键脚本（Ubuntu / Debian / CentOS）

```bash
# 1) 把整个 cmcc_server 目录传到服务器，例如
scp -r cmcc_server root@你的服务器IP:/opt/

# 2) 登录服务器执行
cd /opt/cmcc_server
bash deploy.sh            # 默认端口 8765
# 或指定端口:  CMCC_PORT=80 bash deploy.sh
```

脚本会**先跑自检**（不通过会提示并让你确认），再装成 systemd 服务（开机自启、崩溃自动重启），访问 `http://服务器IP:8765/`。

**记得在云厂商安全组放行端口**；只有 22/80/443 放行的服务器建议 `CMCC_PORT=80`。

### 方式 B：Docker

```bash
cd cmcc_server
docker build -t cmcc-keepalive .
docker run -d --name cmcc-keepalive --restart unless-stopped \
  -p 8765:8765 \
  -e CMCC_PANEL_PASS=你的面板密码 \
  -v $(pwd)/data:/app/data \
  cmcc-keepalive
```

### 方式 C：裸跑 / nohup

```bash
cd cmcc_server
python3 -u server.py --port 8765
# 后台常驻：
#   setsid nohup python3 -u server.py --port 8765 > run.log 2>&1 &
```

要求：**Python 3.9+，无任何 pip 依赖**（二维码库 qrcodegen.py 随仓库附带，纯标准库实现）。

### 安全建议（公网部署）

```bash
# 设置面板访问密码（设置后需用 ?token=密码 或登录框进入）
export CMCC_PANEL_PASS=你的密码
python3 -u server.py --port 8765
```

或前置 nginx 加 HTTPS 反代，只在内网/白名单 IP 开面板。

---

## 三、使用

1. 打开面板 → **添加账号**（三种方式任选）：
   - **扫码登录**：切到「扫码登录」Tab，二维码自动生成，用「移动爱家（原和家亲）」APP 扫码确认即可（已扫待确认/失效都会自动提示，失效自动换新码）
     > ⚠️ **必须用 APP 里自带的「扫一扫」**（首页右上角），**不能用微信 / 系统相机**。
     > 二维码内容是官方的 `http://hsop.komect.com:18080/appdl/redirect.html?token=...` 跳转地址，
     > 只有 APP 内置扫码器认得它并走登录确认；普通相机扫只会打开一个网页，看起来"不是登录链接"。
   - **短信验证码登录**：填手机号 → 发送验证码 → 输入验证码 → 「登录并保活」
   - **账号密码登录**：填账号密码（如提示需要图形验证码，点「获取图形验证码」）
2. 登录成功后自动拉取名下**所有云电脑**并开始保活。

### 账号卡片（每个账号一张卡）

卡片第一行就是主操作，从左到右一目了然：

| 按钮 / 信息 | 作用 |
|---|---|
| **账号名** | 默认显示手机号；在「修改设置」里可改成备注名（如「风自冷」） |
| **状态徽标** | 正常保活 / 已停止 / 登录已失效 / 已到期停止 |
| **🔍 检测是否在线** | 立即 `checkToken` + 拉设备列表 + 首台设备实测心跳。**改过密码、在别处登录、会话被顶**时，这里会直接报「不在线」，并在卡片里列出每一步的返回码 |
| **▶ 启动保活** | 启动。会清零所有计时，立刻做一次登录态校验 + 拉设备 + 保活一次 |
| **■ 停止保活** | 停止。立即不再心跳 / 上报 / 定时保活，账号与设置保留 |
| **⚡ 立即保活一次** | 不等间隔，马上对每台设备发一次 `getFirmAuth` 重置计时器 |
| **⚙ 修改设置** | 备注名 / 到期时间 / 保活间隔 / 关机自动唤醒 |
| **删除** | 移除账号（其云电脑停止保活） |
| **⏰ 到期时间** | 到点**强制停止保活**（`enabled=false`，状态变「已到期停止」），不会偷偷继续续保。留空＝不限期 |
| **动态日志** | 页面底部实时滚动，能看到每次心跳、上报、保活、检测、停止 |

### 保活设置（对应「我云电脑 24 小时不动会关机，我就设 23 小时」）

- **卡片底部**：`每 [23] 小时主动保活一次 [保存]`——直接填小时数，保存后立即生效（改小后下一轮就触发）。
- **或点「修改设置」**：
  - **保活间隔**：以**小时**为单位（可填 0.5 这种小数）。云电脑静止 24 小时会关机 → 就设 **23**，
    每 23 小时主动保活一次，在计时器到期前把时间重置。填 **0** ＝ 关闭定时保活（只靠 30 秒心跳）。
  - **到期时间**：`datetime-local` 选择器 + `+1天 / +7天 / +30天 / 设为不限期` 快捷键。
  - **关机自动唤醒**：检测到云电脑已关机时用 `getFirmAuth` 兜底开机。

3. 面板其他功能：
   - 每台云电脑行末开关：单台设备停/启保活
   - 「刷新设备」：立即重新拉取设备列表；「立即唤醒」：手动触发一次
   - 顶部「全局」开关：全部账号一键暂停
   - 顶部总览条：账号数 / 云电脑数 / **正在保活**（心跳 2 分钟内）/ **需要关注**（失效与到期账号）


### 面板访问密码（公网部署必开）

设置 `CMCC_PANEL_PASS` 后：未认证访问 `/` 只会看到一个登录页，所有 `/api/*` 返回 401；
带正确密码访问 `/?token=密码` 会下发 30 天 Cookie，之后直接打开即可。

```bash
# systemd 里加一行 Environment=CMCC_PANEL_PASS=你的密码，然后
systemctl restart cmcc-keepalive
```

### 导入已有会话（不想重新登录时）

服务器上没有客户端，可把已有登录态导进去：

```bash
# 从官方客户端配置导入（Windows 客户端）
python server.py --import-local

# 或手动传 token（userId 与 sohoToken 来自客户端 config.json）
python server.py --import-token <userId> <sohoToken> [备注名]
# 例：python server.py --import-token 10000001 0123456789abcdef0123456789abcdef myaccount
```

> ⚠️ 注意：`sohoToken` 与**设备指纹（deviceId）绑定**。`--import-local` 会连原 deviceId 一起导入；
> 手动导入时服务器会生成新 deviceId，若校验失败请改用短信登录。
> 另外导入的会话与原电脑客户端**共用同一个设备身份**，客户端再次登录后旧 token 会失效，此时在面板里用短信重新登录即可。

---

## 四、HTTP API（可对接自己的系统）

| 方法 | 路径 | 参数 | 说明 |
|---|---|---|---|
| GET | `/api/state` | — | 全部账号/设备状态快照 |
| GET | `/api/logs?since=<id>` | — | 增量日志 |
| POST | `/api/qrlogin/start` | — | 生成扫码登录二维码（返回 PNG base64 + sid） |
| GET | `/api/qrlogin/poll?sid=<sid>` | — | 轮询扫码状态（pending/scaning/success/expired） |
| POST | `/api/sms/send` | `{phone}` | 发送短信验证码 |
| POST | `/api/account/sms` | `{phone, code}` | 短信登录并加入保活 |
| GET | `/api/captcha?login=<账号>` | — | 获取图形验证码（base64） |
| POST | `/api/account/pwd` | `{username, password, vcode}` | 密码登录并加入保活 |
| POST | `/api/account/import` | `{userId, sohoToken, login?, deviceId?}` | 导入已有会话 |
| POST | `/api/account/relogin` | `{key, code}` | 短信验证码重新登录（刷 token） |
| POST | `/api/account/start` | `{key}` | **启动保活**（清零计时，立刻校验+保活）。已过到期时间会被拒绝 |
| POST | `/api/account/stop` | `{key}` | **停止保活**（不再心跳/上报/保活） |
| POST | `/api/account/check` | `{key}` | **检测是否在线**：返回 `{online: true/false/null, detail:[{step,code,msg}]}` |
| POST | `/api/account/keepalive_now` | `{key}` | **立即执行一次保活**（忽略间隔计时） |
| POST | `/api/account/update` | `{key, remark?, expire_at?, interval_hours?\|interval_min?, wake_on_off?}` | 修改设置；`expire_at` 支持 `2026-10-09 18:00` / ISO / unix 秒 / 空=不限期 |
| POST | `/api/account/toggle` | `{key, enabled}` | 兼容旧接口，等价于 `/start` 或 `/stop` |
| POST | `/api/device/toggle` | `{key, sid, enabled}` | 单设备保活开关 |
| POST | `/api/account/keepalive` | `{key, interval, wake_on_off}` | 定时保活间隔（分钟，上限 43200＝30 天）与关机唤醒开关 |
| POST | `/api/account/refresh` | `{key}` | 刷新设备列表 |
| POST | `/api/account/wake` | `{key}` | 手动保活/唤醒全部设备 |
| POST | `/api/account/remove` | `{key}` | 删除账号 |
| POST | `/api/settings` | `{global_enabled}` | 全局开关 |

---

## 五、常见问题

**Q：能保证 24 小时不关机吗？**
定时保活（默认每 6 小时主动"用一次"）+ 30 秒心跳 + 2 分钟在线上报 + 关机自动唤醒，服务器侧能做的信号已全部覆盖。如果你的云电脑实测是在"闲置约 24 小时"后关机，默认配置就能让它永不到期；若平台有独立的计费时长策略（如算时专区计量），任何客户端挂机都无法绕过，需要留意套餐余量。

**Q：面板账号显示「登录已失效」（4015）？心跳日志一直刷"用户未登录"？**
这是因为账号是用 `--import-local` 导入的**本机客户端 token**——它与你电脑上的官方客户端
**共用同一个设备身份**。**只要你在电脑上打开/重新登录了官方客户端，服务端就会把服务器上这个旧 token 顶掉。**

解决办法（二选一，推荐后者）：
1. 面板上点该账号的「**短信重登**」→ 输入验证码，服务器会拿到新 token（但设备身份还是原来那个，仍可能再被顶）
2. **更好**：用面板的「**扫码登录**」或「短信验证码登录」在服务器上**新建一个独立账号会话**
   （新设备指纹），与原电脑客户端互不干扰，之后不会再互相顶掉。旧的导入账号可以删掉。

已内置的保护：失效账号会**停止心跳与上报**（不再刷 4015 日志），只每 10 分钟探活一次；
面板会显示红色提示条并给出一键重登入口。

**Q：面板提示 `[-2] network error: Tunnel connection failed: 502 Bad Gateway`？**
这是 Python 走了系统代理（环境变量 `HTTP_PROXY`/`HTTPS_PROXY`），而代理本身不可用。
新版本已内置**代理自适应**：默认直连官方接口，失败自动回退系统代理并记住有效出口，
两种出口都试过仍失败才报错。若你的网络**必须**走代理，用 `CMCC_USE_PROXY=1` 启动即可强制优先代理。
改完代码记得重启服务（systemd: `sudo systemctl restart cmcc-keepalive`）。

**Q：定时保活间隔设多少合适？**
默认 360 分钟（6 小时）即可——一天主动保活 4 次，远早于 24 小时到期点。想更保守可设 240（4 小时）；最大 1440（24 小时，等于每天一次，卡点风险高不建议）。设 0 则关闭定时保活，只靠心跳 + 关机唤醒。

**Q：会不会影响我在电脑上正常使用？**
不会。协议登录是"服务器作为一台独立设备"，与原电脑的客户端互不干扰；两边可同时在线（不同 deviceId）。
若你用的是 `--import-local` 导入的会话，则与原客户端共用同一设备身份，建议改用短信登录方式。

**Q：token 多久会过期？**
不确定（平台策略）。引擎每 2 小时主动校验一次，失效会在面板标红；短信重登即可恢复。

**Q：面板日志里 `4041` 是什么？**
云电脑正常业务态（"解锁状态"），不是错误。`4043` 才是"被其他设备占用/已回收"。

**Q：安全吗？**
账号 token 只保存在本机 `data/accounts.json`，所有请求直达官方服务器 `soho.komect.com`，无第三方中转。密码仅用于登录请求，经客户端同款 RSA 加密后发出，不落盘。
