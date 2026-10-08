# -*- coding: utf-8 -*-
"""
CMCC 移动云电脑 (soho.komect.com) 协议客户端 —— 服务器版
=========================================================
纯 Python 标准库实现，无第三方依赖。

协议要点（由客户端 app.asar 源码逆向所得）：
  签名  : X-SOHO-Signature = HMAC-SHA256(key=hex2bytes(APP_SECRET),
              f"{METHOD}&{path}&{k1}={v1}&{k2}={v2}...[&body={rsa_cipher_b64}]")
          参与签名的 header 按插入顺序、且跳过空值（登录时 SohoToken/UserId 为空 = 不参与）。
  body  : 每 117 字节切块 -> 左侧补 0x00 至 128 字节 -> RSA_NO_PADDING 加密 -> 拼 base64
          外层 {"data": "<base64>"}
  双层  : 账密登录的 password 字段先单独 RSA_NO_PADDING 加密一次，整个 body 再加密一次。

登录流程（三种，均已对齐客户端行为）：
  A. 短信: POST /terminal/login/sms/send/v1   {phone}
           POST /terminal/login/sms/login/v1  {phone, smsCode}
  B. 账密: POST /terminal/login/verificationCode/v1        (图形验证码, 无参)
           POST /terminal/login/publicKey/v1   {type:1}     (取密码专用公钥)
           POST /terminal/login/namePwdLogin/v1 {username, password, verificationCode, randomCode}
  C. 子账号: POST /terminal/login/home/namePwdLogin/v1 {subAccount, password, verificationCode, randomCode}

保活链路：
  1) /token/checkToken/v1              —— 保持登录态（客户端 2h 一次）
  2) /cc/cloudPc/list/v6 {pageNum:1}   —— 拉取名下全部云电脑（含 vmStatus）
  3) /cc/cloudPc/heartbeat/v2 {userServiceId}   —— 云电脑心跳（客户端 30s 一次）
  4) /cc/cloudPc/infoReport/v2 {设备信息}        —— 设备在线上报（客户端 2min 一次）
  5) /cc/getFirmAuth/v1 {userServiceId}         —— 连接凭证；云电脑关机/闲置时调用可触发开机
"""

import base64
import hashlib
import hmac
import json
import os
import random
import ssl
import time
import urllib.error
import urllib.request

# ----------------------------------------------------------------------------
# 常量（取自客户端 config.prod.win.js）
# ----------------------------------------------------------------------------
# 取自客户端 config.prod.win.js。可用环境变量覆盖（换密钥时不用改代码）
APP_KEY = os.environ.get('CMCC_APP_KEY') or \
    'b866539514246c187171f759ff409de25149407fcdada3c678a0c39c233cefb1'
APP_SECRET = os.environ.get('CMCC_APP_SECRET') or \
    'b5630ba3e5e95defd08306b2c1069c8b4b791098d726f107ad747a216f57eaf5'
BASE_URL = 'https://soho.komect.com'
VERSION = '2.23.1'
VERSION_NUM = '2230100'
RELEASE_NUM = '1'
GIT_NUM = 'dd2313e'

# 业务码
CODE_OK = 2000
CODE_UNTOKEN = (4015, 4016, 4017, 4200)      # 登录态失效
CODE_H5_LOGINED = 4201
CODE_LOCK_SCREEN = (4039, 4040, 4041, 4042)  # 锁屏/解锁态（非错误）
CODE_OTHER_LOGIN = 4043                      # 云电脑被其他设备占用/已回收
CODE_NEED_VC = 4121                          # 需要图形验证码
CODE_NEED_ACTIVATE = 5121                    # 需要首次激活
CODE_IN_ACTIVATE = 5120                      # 初始化中
CODE_INIT_ERR = 5125                         # 初始化失败


# ----------------------------------------------------------------------------
# DER / RSA（纯整数运算，无 pycryptodome 依赖）
# ----------------------------------------------------------------------------
def _der(data, i=0):
    tag = data[i]
    i += 1
    ln = data[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[i:i + n], 'big')
        i += n
    return tag, data[i:i + ln], i + ln


def parse_pubkey(b64_key):
    """解析 SubjectPublicKeyInfo base64 -> (n, e)"""
    der = base64.b64decode(b64_key)
    _, outer, _ = _der(der, 0)
    _, _, i = _der(outer, 0)            # AlgorithmIdentifier
    _, bits, _ = _der(outer, i)         # BIT STRING
    inner = bits[1:]
    _, rsa_seq, _ = _der(inner, 0)
    _, nb, i2 = _der(rsa_seq, 0)
    _, eb, _ = _der(rsa_seq, i2)
    return int.from_bytes(nb, 'big'), int.from_bytes(eb, 'big')


def rsa_no_pad_encrypt(chunk: bytes, n, e, size=128):
    padded = b'\x00' * (size - len(chunk)) + chunk
    c = pow(int.from_bytes(padded, 'big'), e, n)
    return c.to_bytes(size, 'big')


def rsa_encrypt_long(plain: bytes, n, e, size=128, chunk_len=117):
    """分块加密（对应客户端 createEncryptData）"""
    out = b''
    for i in range(0, max(len(plain), 1), chunk_len):
        out += rsa_no_pad_encrypt(plain[i:i + chunk_len], n, e, size)
    return out


def rsa_encrypt_single(text: str, n, e, size=128):
    """单块加密 base64 —— 对应 mainApi.rsaEncrypt（用于 password 字段）"""
    raw = text.encode('utf-8')
    if len(raw) >= size:
        raise ValueError('password too long for single RSA block')
    return base64.b64encode(rsa_no_pad_encrypt(raw, n, e, size)).decode()


def gen_uuid():
    """对应客户端 generateRandomName(): uuid_ + 32位大写hex(带 v4 版本位)"""
    hx = '0123456789ABCDEF'
    s = [random.choice(hx) for _ in range(32)]
    s[12] = '4'
    s[16] = hx[(int(s[16], 16) & 0x3) | 0x8]
    return 'uuid_' + ''.join(s)


def gen_device_id():
    """生成伪设备指纹: 8位大写序列号-小写MAC，形状与真机一致"""
    letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'
    serial = ''.join(random.choice(letters) for _ in range(8))
    mac = ':'.join('%02x' % random.randint(0, 255) for _ in range(6))
    return '%s-%s' % (serial, mac)


# ---------------------------------------------------------------------------
# 网络出口：代理自适应
# ---------------------------------------------------------------------------
# urllib 默认会读取 HTTP_PROXY/HTTPS_PROXY 环境变量。很多机器上残留的代理
# 会返回 "Tunnel connection failed: 502 Bad Gateway"，导致明明能直连的接口
# 反而打不通。这里默认直连，失败自动回退到系统代理，并记住上次成功的方式。
# 如需强制优先走代理：设置环境变量 CMCC_USE_PROXY=1
# 老服务器 CA 证书过旧导致 certificate verify failed 时：设置 CMCC_INSECURE=1 应急跳过校验
_PREFER_PROXY = os.environ.get('CMCC_USE_PROXY', '0') == '1'
_LAST_OK_DIRECT = not _PREFER_PROXY      # 上次成功的出口（True=直连）
_openers = {}
_SSL_CTX = ssl.create_default_context()
if os.environ.get('CMCC_INSECURE', '0') == '1':
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE


def _get_opener(use_proxy: bool):
    key = 'proxy' if use_proxy else 'direct'
    if key not in _openers:
        handlers = [] if use_proxy else [urllib.request.ProxyHandler({})]
        handlers.append(urllib.request.HTTPSHandler(context=_SSL_CTX))
        _openers[key] = urllib.request.build_opener(*handlers)
    return _openers[key]


def make_device_profile(device_id=None, model='X64', release='10.0.19045'):
    """构造一套稳定的设备信息（appType / romVersion 参与签名，必须持久化）"""
    device_id = device_id or gen_device_id()
    return {
        'deviceId': device_id,
        'appType': 'windows|%s|%s|0|-1|%s|' % (release, model, device_id),
        'romVersion': 'LENOVO-%s' % release,
        'model': model,
        'release': release,
    }


# ----------------------------------------------------------------------------
# 协议错误
# ----------------------------------------------------------------------------
class CmccError(Exception):
    def __init__(self, code, msg, business_code=None):
        super().__init__('[%s] %s' % (code, msg))
        self.code = code
        self.msg = msg
        self.business_code = business_code


class TokenExpired(CmccError):
    pass


# ----------------------------------------------------------------------------
# 协议客户端
# ----------------------------------------------------------------------------
class CMCCApi:
    """一个实例 = 一个账号的会话。线程安全由调用方（加锁）保证。"""

    def __init__(self, device=None, soho_token='', user_id='', timeout=20):
        self.device = device or make_device_profile()
        self.soho_token = soho_token
        self.user_id = str(user_id or '')
        self.timeout = timeout
        self._n = None          # body 加密公钥（encryptKey）
        self._e = None
        self._login_n = None    # 密码专用公钥（publicKey type=1）
        self._login_e = None

    # ---------------- 底层 HTTP ----------------
    def _headers(self, ts):
        d = self.device
        h = {}
        h['X-SOHO-AppKey'] = APP_KEY
        h['X-SOHO-AppType'] = d.get('appType', '')
        h['X-SOHO-ClientVersion'] = VERSION
        h['X-SOHO-DeviceId'] = d.get('deviceId', '')
        h['X-SOHO-RomVersion'] = d.get('romVersion', '')
        h['X-SOHO-SohoToken'] = self.soho_token or ''
        h['X-SOHO-Timestamp'] = ts
        h['X-SOHO-UserId'] = self.user_id
        h['X-SOHO-Uuid'] = gen_uuid()
        h['X-SOHO-VersionNum'] = VERSION_NUM
        return h

    @staticmethod
    def _sign(method, path, headers, payload):
        arr = ['%s=%s' % (k, v) for k, v in headers.items() if v]
        s = '%s&%s&%s' % (method, path, '&'.join(arr))
        if payload and 'data' in payload:
            s += '&body=%s' % payload['data']
        return hmac.new(bytes.fromhex(APP_SECRET), s.encode('utf-8'), hashlib.sha256).hexdigest()

    def _ua(self):
        return 'jtydn-Windows-%s(%s.%s.%s)' % (VERSION, RELEASE_NUM, GIT_NUM, time.strftime('%m%d'))

    def request(self, path, data=None, prefix='/terminal', retry=2, need_pubkey=True):
        """核心请求。data=None 表示无 body（如 checkToken / encryptKey）。"""
        if data is not None and need_pubkey:
            if self._n is None:
                self.fetch_encrypt_key()
        url = BASE_URL + prefix + path
        global _LAST_OK_DIRECT
        last_err = None
        for attempt in range(retry + 1):
            # 首选上次成功的出口；只有最后一次重试才额外尝试另一种出口，
            # 避免服务器断网时每个请求都双倍等待、拖慢整个保活引擎。
            pref = 'direct' if _LAST_OK_DIRECT else 'proxy'
            modes = [pref] if attempt < retry else [
                pref, 'proxy' if pref == 'direct' else 'direct']
            for mode in modes:
                try:
                    ts = str(int(time.time() * 1000))
                    h = self._headers(ts)
                    payload = None
                    if data is not None:
                        raw = json.dumps(data, ensure_ascii=False,
                                         separators=(',', ':')).encode('utf-8')
                        payload = {'data': base64.b64encode(
                            rsa_encrypt_long(raw, self._n, self._e)).decode()}
                    h['X-SOHO-Signature'] = self._sign('POST', path, h, payload)
                    body = json.dumps(payload).encode('utf-8') if payload else None
                    req = urllib.request.Request(url, data=body, method='POST')
                    for k, v in h.items():
                        req.add_header(k, v)
                    req.add_header('Content-Type', 'application/json')
                    req.add_header('User-Agent', self._ua())
                    with _get_opener(mode == 'proxy').open(req, timeout=self.timeout) as r:
                        txt = r.read().decode('utf-8')
                    _LAST_OK_DIRECT = (mode == 'direct')
                    try:
                        return json.loads(txt)
                    except Exception:
                        return {'code': -1, 'msg': 'bad json', '_raw': txt[:500]}
                except urllib.error.HTTPError as ex:
                    # 有 HTTP 响应说明链路是通的，不必换出口，只按 retry 重试
                    last_err = 'HTTP %s: %s' % (ex.code, ex.read().decode('utf-8', 'replace')[:200])
                    break
                except Exception as ex:
                    last_err = '%s: %s' % (type(ex).__name__, ex)
                    continue      # 换另一种出口重试
            time.sleep(1.0 * (attempt + 1))
        msg = 'network error: %s' % last_err
        low = (last_err or '').lower()
        if any(k in low for k in ('tunnel', 'proxy', '502', '407', 'bad gateway')):
            msg += '（已尝试直连与系统代理两种出口；可检查系统代理是否可用，' \
                   '或用 CMCC_USE_PROXY=1 强制走代理）'
        return {'code': -2, 'msg': msg}

    def call(self, path, data=None, **kw):
        """request 的严格版：非 2000 抛异常（锁屏/需激活等业务态除外）"""
        r = self.request(path, data, **kw)
        code = r.get('code')
        if code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
            raise TokenExpired(code, r.get('msg', ''))
        return r

    # ---------------- 公钥 ----------------
    def fetch_encrypt_key(self):
        """GET body 加密公钥。失败抛异常。"""
        r = self.request('/login/encryptKey/v1', None, need_pubkey=False)
        if r.get('code') != CODE_OK or not r.get('data'):
            raise CmccError(r.get('code'), '获取加密公钥失败: %s' % r.get('msg'))
        self._n, self._e = parse_pubkey(r['data'])
        return r['data']

    def fetch_login_pubkey(self):
        """账密登录专用公钥 /login/publicKey/v1 {type:1}"""
        r = self.request('/login/publicKey/v1', {'type': 1})
        if r.get('code') != CODE_OK or not r.get('data'):
            raise CmccError(r.get('code'), '获取登录公钥失败: %s' % r.get('msg'))
        self._login_n, self._login_e = parse_pubkey(r['data'])
        return r['data']

    # ---------------- 登录 ----------------
    def send_sms(self, phone):
        """发送短信验证码 /login/sms/send/v1"""
        return self.request('/login/sms/send/v1', {'phone': phone})

    def sms_login(self, phone, sms_code):
        """短信登录 /login/sms/login/v1"""
        r = self.request('/login/sms/login/v1', {'phone': phone, 'smsCode': sms_code})
        if r.get('code') == CODE_OK and r.get('data'):
            self._apply_login(r['data'])
        return r

    def get_captcha(self):
        """图形验证码 /login/verificationCode/v1 -> {verificationCode, randomCode}"""
        return self.request('/login/verificationCode/v1', None)

    def pwd_login(self, username, password, verification_code, random_code):
        """账密登录 /login/namePwdLogin/v1（双层 RSA）"""
        if self._login_n is None:
            self.fetch_login_pubkey()
        enc_pwd = rsa_encrypt_single(password, self._login_n, self._login_e)
        r = self.request('/login/namePwdLogin/v1', {
            'username': username,
            'password': enc_pwd,
            'verificationCode': verification_code or '',
            'randomCode': random_code or '',
        })
        if r.get('code') == CODE_OK and r.get('data'):
            self._apply_login(r['data'])
        return r

    def sub_pwd_login(self, sub_account, password, verification_code, random_code):
        """子账号登录 /login/home/namePwdLogin/v1"""
        if self._login_n is None:
            self.fetch_login_pubkey()
        enc_pwd = rsa_encrypt_single(password, self._login_n, self._login_e)
        r = self.request('/login/home/namePwdLogin/v1', {
            'subAccount': sub_account,
            'password': enc_pwd,
            'verificationCode': verification_code or '',
            'randomCode': random_code or '',
        })
        if r.get('code') == CODE_OK and r.get('data'):
            self._apply_login(r['data'])
        return r

    def _apply_login(self, data):
        self.soho_token = data.get('sohoToken') or self.soho_token
        if data.get('userId'):
            self.user_id = str(data['userId'])

    # ---------------- 保活 / 业务 ----------------
    def check_token(self):
        """/token/checkToken/v1 —— 登录态校验（保活其一）"""
        return self.request('/token/checkToken/v1', None)

    def list_cloud_pcs(self):
        """拉取名下全部云电脑 /cc/cloudPc/list/v6  ->  [item, ...]"""
        out, page = [], 1
        while page <= 10:
            r = self.request('/cc/cloudPc/list/v6', {'pageNum': page})
            if r.get('code') != CODE_OK:
                if page == 1:
                    raise CmccError(r.get('code'), r.get('msg', 'list failed'))
                break
            d = r.get('data') or {}
            items = d.get('list') or []
            out.extend(items)
            total = d.get('total') or 0
            if len(out) >= total or not items:
                break
            page += 1
        return out

    def heartbeat(self, user_service_id):
        """/cc/cloudPc/heartbeat/v2 —— 云电脑心跳（核心保活信号）"""
        return self.request('/cc/cloudPc/heartbeat/v2', {'userServiceId': int(user_service_id)})

    def info_report(self, payload=None):
        """/cc/cloudPc/infoReport/v2 —— 设备在线上报"""
        payload = payload or {
            'cpuModel': 'Intel(R) Core(TM) i5-8500 CPU @ 3.00GHz',
            'cpuUsageRate': '%d%%' % random.randint(5, 25),
            'memory': '16GB',
            'memoryUsageRate': '%d%%' % random.randint(20, 60),
            'storage': '256GB',
            'storageUsageRate': '%d%%' % random.randint(30, 70),
            'deviceResolutionRatio': '1920*1080',
            'width': '1920',
            'height': '1080',
            'deviceIp': '192.168.1.100',
        }
        return self.request('/cc/cloudPc/infoReport/v2', payload)

    def firm_auth(self, user_service_id):
        """/cc/getFirmAuth/v1 —— 连接凭证。
        云电脑关机/闲置时调用会触发服务端开机并重置空闲计时，是保活兜底手段。"""
        return self.request('/cc/getFirmAuth/v1', {'userServiceId': int(user_service_id)})

    def pc_detail(self, user_service_id):
        return self.request('/cc/cloudPc/detail/v1', {'userServiceId': int(user_service_id)})

    def collect_info(self, type_='0', method='1'):
        """/cc/collectInfo/v1 —— 客户端登录后必发的协议记录，跟随行为更自然"""
        return self.request('/cc/collectInfo/v1', {'type': type_, 'collectMethod': method})

    # ---------------- 扫码登录 ----------------
    def get_lg_token_url(self):
        """/token/getLgTokenUrl/v1 —— 取二维码内容 {url, token}
        客户端把 url 渲染成二维码，用「移动爱家（原和家亲）」APP 扫。"""
        return self.request('/token/getLgTokenUrl/v1', None)

    def check_login_status(self, qr_token):
        """/login/checkLoginStatus/v1 {token} —— 轮询扫码结果
        2000=已确认(返回登录数据)  6002=已扫待确认  6004=二维码失效"""
        r = self.request('/login/checkLoginStatus/v1', {'token': qr_token})
        if r.get('code') == CODE_OK and r.get('data'):
            self._apply_login(r['data'])
        return r
