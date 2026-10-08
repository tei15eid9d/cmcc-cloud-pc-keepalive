# -*- coding: utf-8 -*-
"""
CMCC 移动云电脑 · 服务器版保活面板
=====================================
零依赖（Python 标准库），可直接部署到 Linux/Windows 服务器。

功能：
  * 协议登录（短信验证码 / 账号密码），不依赖官方客户端
  * 多账号管理，每账号独立设备指纹与会话
  * 单账号下所有云电脑全部保活（30s 心跳 + 2min 在线上报 + 2h 登录态校验）
  * 关机检测与自动唤醒（getFirmAuth 触发开机）
  * Web 面板：账号管理 / 实时日志 / 一键暂停 / 手动唤醒

启动：
  python3 server.py --port 8765
  # 可选：CMCC_PANEL_PASS=yourpass 加访问密码
"""
import argparse
import base64
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmcc_api import (  # noqa: E402
    CMCCApi, CmccError, TokenExpired, make_device_profile,
    CODE_OK, CODE_UNTOKEN, CODE_H5_LOGINED, CODE_LOCK_SCREEN, CODE_OTHER_LOGIN,
    CODE_NEED_VC, CODE_NEED_ACTIVATE, CODE_IN_ACTIVATE, CODE_INIT_ERR,
)
from qr import make_qr_png  # noqa: E402  零依赖二维码编码

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATA_FILE = os.path.join(DATA_DIR, 'accounts.json')
PANEL_FILE = os.path.join(BASE_DIR, 'panel.html')

# 保活节奏（秒）
HB_INTERVAL = 30          # 云电脑心跳（对齐客户端 cloudPcheartbeatTime=30000）
REPORT_INTERVAL = 120     # 设备在线上报（对齐客户端 resolutionRefreshTime=120000）
TOKEN_INTERVAL = 7200     # 登录态校验（对齐客户端 tokenCheckFreq=7200000 ms）
SCAN_INTERVAL = 300       # 设备列表扫描 / 关机检测
WAKE_COOLDOWN = 600       # 单设备唤醒冷却，防止 getFirmAuth 风暴
TICK = 5                  # 引擎调度粒度

VM_RUNNING = 3            # vmStatus 3=运行中；另 1 亦视为运行中(vmStatusShow)
VM_OFF = 0                # 0=已关机
VM_OPENING = 2            # 2=开机中
VM_LINKING = 12           # 12=连接中

DEFAULT_KEEPALIVE_INTERVAL = 360   # 定时保活间隔（分钟）：默认 6 小时主动保活一次
                                   # 目的：在平台 24 小时计时器到期前主动重置，不等关机再救
MAX_KEEPALIVE_MIN = 43200          # 定时保活间隔上限：30 天（43200 分钟）
CODE_SCANING = 6002                # 扫码登录：已扫待确认
CODE_QRCODE_EXPIRED = 6004         # 扫码登录：二维码失效


def now_ts():
    return int(time.time())


def fmt_ts(ts):
    """时间戳 -> 本地可读字符串（日志/面板用）"""
    if not ts:
        return '—'
    try:
        return time.strftime('%m-%d %H:%M', time.localtime(int(ts)))
    except Exception:
        return str(ts)


def parse_expire(raw):
    """解析到期时间：支持 unix 秒 / 毫秒 / 'YYYY-MM-DD HH:MM' / ISO / 空值。
    返回 int 时间戳；0 表示不限期；None 表示格式错误。"""
    if raw is None:
        return 0
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        v = int(raw)
        if v > 10 ** 12:        # 毫秒
            v //= 1000
        return max(0, v)
    s = str(raw).strip()
    if not s or s.lower() in ('0', 'null', 'none', 'nan', '-'):
        return 0
    if re.fullmatch(r'\d{10,13}', s):
        v = int(s)
        if v > 10 ** 12:
            v //= 1000
        return v
    s2 = s.replace('T', ' ').replace('/', '-')
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return int(time.mktime(time.strptime(s2, fmt)))
        except ValueError:
            continue
    return None


def ensure_defaults(acc):
    """老账号补齐新字段，避免升级后 KeyError / 面板空列"""
    if acc is None:
        return acc
    acc.setdefault('remark', '')
    acc.setdefault('expire_at', 0)
    acc.setdefault('enabled', True)
    acc.setdefault('keepalive_interval', DEFAULT_KEEPALIVE_INTERVAL)
    acc.setdefault('wake_on_off', True)
    acc.setdefault('status', 'idle')
    acc.setdefault('status_msg', '')
    if acc.get('enabled') is False and acc.get('status') == 'ok':
        # 曾经被停过的账号，状态归一到 stopped
        acc['status'] = 'stopped'
    return acc


# ---------------------------------------------------------------------------
# 日志总线
# ---------------------------------------------------------------------------
class LogBus:
    def __init__(self, maxlen=1000):
        self.buf = deque(maxlen=maxlen)
        self.seq = 0
        self.lock = threading.Lock()

    def add(self, level, msg, account=''):
        with self.lock:
            self.seq += 1
            self.buf.append({
                'id': self.seq, 't': now_ts(),
                'level': level, 'account': account, 'msg': str(msg)[:400],
            })
            return self.seq

    def info(self, msg, account=''):
        return self.add('info', msg, account)

    def ok(self, msg, account=''):
        return self.add('ok', msg, account)

    def warn(self, msg, account=''):
        return self.add('warn', msg, account)

    def error(self, msg, account=''):
        return self.add('error', msg, account)

    def since(self, since_id, limit=300):
        with self.lock:
            items = [x for x in self.buf if x['id'] > since_id]
        return items[-limit:]


LOG = LogBus()


# ---------------------------------------------------------------------------
# 账号存储
# ---------------------------------------------------------------------------
class AccountStore:
    """accounts.json 持久化 + 内存状态。所有读写经 self.lock。"""

    def __init__(self, path=DATA_FILE):
        self.path = path
        self.lock = threading.RLock()
        self.accounts = {}   # key -> dict
        self.settings = {'global_enabled': True}
        self.load()

    # ---- 持久化 ----
    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            self.accounts = {a['key']: a for a in raw.get('accounts', [])}
            self.settings.update(raw.get('settings', {}))
        except Exception as e:
            LOG.error('读取账号库失败: %s' % e)

    def save(self):
        with self.lock:
            tmp = self.path + '.tmp'
            data = {'accounts': list(self.accounts.values()), 'settings': self.settings}
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)

    # ---- 查询 ----
    def get(self, key):
        with self.lock:
            return self.accounts.get(key)

    def all(self):
        with self.lock:
            return list(self.accounts.values())

    def find_by_login(self, login):
        with self.lock:
            for a in self.accounts.values():
                if a.get('phone') == login or a.get('username') == login:
                    return a
        return None

    # ---- 变更 ----
    def add_or_update(self, login, login_type, token_data, device=None):
        """登录成功后建号。返回 (account, created)"""
        with self.lock:
            acc = self.find_by_login(login)
            created = False
            if acc is None:
                created = True
                acc = {
                    'key': secrets.token_hex(6),
                    'login': login,
                    'login_type': login_type,
                    'phone': token_data.get('phone') or '',
                    'username': token_data.get('username') or '',
                    'nickname': token_data.get('nickname') or '',
                    'userId': str(token_data.get('userId') or ''),
                    'sohoToken': token_data.get('sohoToken') or '',
                    'isSubAccount': bool(token_data.get('isSubAccount') or
                                         token_data.get('accountType') == 'subAccount'),
                    'device': device or make_device_profile(),
                    'remark': '',                                       # 备注名（面板显示用，如「风自冷」）
                    'expire_at': 0,                                     # 到期时间戳；到点强制停止保活（0=不限期）
                    'enabled': True,
                    'keepalive_interval': DEFAULT_KEEPALIVE_INTERVAL,   # 分钟，0=关闭定时保活
                    'wake_on_off': True,                                # 关机自动唤醒兜底
                    'status': 'idle',
                    'status_msg': '',
                    'createdAt': now_ts(),
                    'last_token_check': 0,
                    'last_scan': 0,
                    'last_report': 0,
                    'devices': [],
                    'totals': {'hb_ok': 0, 'hb_err': 0, 'wakes': 0, 'reports': 0, 'token_ok': 0},
                }
                self.accounts[acc['key']] = acc
            else:
                acc['sohoToken'] = token_data.get('sohoToken') or acc['sohoToken']
                acc['userId'] = str(token_data.get('userId') or acc['userId'])
                acc['phone'] = token_data.get('phone') or acc.get('phone')
                acc['username'] = token_data.get('username') or acc.get('username')
                acc['nickname'] = token_data.get('nickname') or acc.get('nickname')
                acc['login_type'] = login_type
                acc['status'] = 'idle'
                acc['status_msg'] = ''
            self.save()
            return acc, created

    def remove(self, key):
        with self.lock:
            acc = self.accounts.pop(key, None)
            self.save()
            return acc

    def touch(self, key, **fields):
        with self.lock:
            acc = self.accounts.get(key)
            if acc:
                acc.update(fields)

    def device_of(self, key, sid):
        with self.lock:
            acc = self.accounts.get(key)
            if not acc:
                return None
            for d in acc.get('devices', []):
                if str(d.get('userServiceId')) == str(sid):
                    return d
        return None

    def totals(self, acc):
        with self.lock:
            t = acc.setdefault('totals', {})
            for k in ('hb_ok', 'hb_err', 'wakes', 'reports', 'token_ok', 'auths', 'auth_err'):
                t.setdefault(k, 0)
            return t


STORE = AccountStore()


# ---------------------------------------------------------------------------
# 会话客户端（账号 -> CMCCApi 缓存）
# ---------------------------------------------------------------------------
class ClientPool:
    def __init__(self):
        self.lock = threading.Lock()
        self.pool = {}

    def get(self, acc):
        with self.lock:
            c = self.pool.get(acc['key'])
            if c is None:
                c = CMCCApi(device=acc.get('device'),
                            soho_token=acc.get('sohoToken', ''),
                            user_id=acc.get('userId', ''), timeout=15)
                self.pool[acc['key']] = c
            # 同步最新 token（可能刚被刷新）
            c.soho_token = acc.get('sohoToken') or c.soho_token
            c.user_id = str(acc.get('userId') or c.user_id or '')
            return c

    def drop(self, key):
        with self.lock:
            self.pool.pop(key, None)


POOL = ClientPool()

# 登录过程中的临时会话（未登录成功前）：login -> {api, randomCode, captcha_img, ts}
TEMP_SESSIONS = {}
TEMP_LOCK = threading.Lock()
TEMP_TTL = 600


def temp_session(login):
    with TEMP_LOCK:
        # 清理过期
        for k in list(TEMP_SESSIONS):
            if now_ts() - TEMP_SESSIONS[k]['ts'] > TEMP_TTL:
                TEMP_SESSIONS.pop(k, None)
        s = TEMP_SESSIONS.get(login)
        if s is None:
            s = {'api': CMCCApi(timeout=15), 'randomCode': '', 'ts': now_ts()}
            TEMP_SESSIONS[login] = s
        s['ts'] = now_ts()
        return s


# ---------------------------------------------------------------------------
# 保活引擎
# ---------------------------------------------------------------------------
def vm_is_on(dev):
    return dev.get('vmStatus') in (1, VM_RUNNING, VM_OPENING, VM_LINKING)


def refresh_devices(acc, api, do_wake=True):
    """拉取云电脑列表，合并到 acc['devices']；返回列表。
    新增设备默认启用保活；已关机设备触发唤醒。"""
    items = api.list_cloud_pcs()
    old = {str(d['userServiceId']): d for d in acc.get('devices', [])}
    new_devices = []
    for it in items:
        sid = it.get('userServiceId')
        if sid is None:
            continue
        sid = int(sid)
        prev = old.get(str(sid), {})
        dev = {
            'userServiceId': sid,
            'vmName': it.get('vmName') or prev.get('vmName') or '',
            'skuName': it.get('skuName') or '',
            'skuSpecStr': it.get('skuSpecStr') or '',
            'vmStatus': it.get('vmStatus'),
            'vmStatusShow': it.get('vmStatusShow') or '',
            'spuCode': it.get('spuCode') or '',
            'cloudPcType': it.get('cloudPcType'),
            'enabled': prev.get('enabled', True),
            'last_heartbeat': prev.get('last_heartbeat', 0),
            'hb_code': prev.get('hb_code'),
            'hb_msg': prev.get('hb_msg', ''),
            'last_wake': prev.get('last_wake', 0),
            'wake_count': prev.get('wake_count', 0),
            'last_auth': prev.get('last_auth', 0),
            'auth_count': prev.get('auth_count', 0),
            'auth_kind': prev.get('auth_kind', ''),
            'auth_msg': prev.get('auth_msg', ''),
        }
        new_devices.append(dev)
    acc['devices'] = new_devices
    STORE.save()

    # 兜底：检测到已关机时自动唤醒（受账号的 wake_on_off 开关控制）
    if do_wake and acc.get('wake_on_off', True):
        for dev in new_devices:
            if dev['enabled'] and dev.get('vmStatus') == VM_OFF:
                if now_ts() - dev.get('last_wake', 0) >= WAKE_COOLDOWN:
                    try:
                        r = api.firm_auth(dev['userServiceId'])
                        dev['last_auth'] = now_ts()
                        dev['last_wake'] = now_ts()
                        dev['auth_msg'] = '[%s] %s' % (r.get('code'), r.get('msg', ''))
                        if r.get('code') == CODE_OK:
                            dev['wake_count'] = dev.get('wake_count', 0) + 1
                            STORE.totals(acc)['wakes'] += 1
                            LOG.ok('已关机 → 触发开机 [%s] %s' % (dev['userServiceId'], dev['vmName']), acc['login'])
                        else:
                            LOG.warn('唤醒返回异常 [%s] %s: %s' % (dev['userServiceId'], r.get('code'), r.get('msg')), acc['login'])
                        STORE.save()
                    except Exception as e:
                        LOG.error('唤醒失败 [%s]: %s' % (dev['userServiceId'], e), acc['login'])
    return new_devices


def account_tick(acc):
    """单个账号的一轮保活。返回 True 表示正常，False 表示本轮异常。"""
    key = acc['key']
    login = acc['login']
    t = now_ts()
    ensure_defaults(acc)
    # 已停止 / 被禁用：不做任何心跳、上报与保活
    if not acc.get('enabled', True):
        return False
    api = POOL.get(acc)
    # 熔断：连续失败后进入冷却，避免断网账号拖慢其他账号、也避免刷屏
    if t < acc.get('cooldown_until', 0):
        return False
    # 登录态已失效：停止心跳/上报，只低频探活，避免每 30 秒刷一条 4015
    if acc.get('status') == 'token_expired':
        if t - acc.get('last_retry', 0) < 600:
            return False
        acc['last_retry'] = t
        try:
            r = api.check_token()
            if r.get('code') == CODE_OK:
                acc['status'] = 'ok'
                acc['status_msg'] = ''
                acc['fail_count'] = 0
                acc['cooldown_until'] = 0
                STORE.save()
                LOG.ok('登录态已恢复，保活继续', login)
                return True
            LOG.warn('登录态仍失效（%s），等待面板重新登录' % r.get('code'), login)
        except Exception as e:
            LOG.warn('探活异常: %s' % e, login)
        finally:
            STORE.save()
        return False
    T = STORE.totals(acc)
    failed = False

    # 1) 登录态校验（默认 2h 一次；token 失效则标记）
    if t - acc.get('last_token_check', 0) >= TOKEN_INTERVAL or acc.get('status') == 'new':
        try:
            r = api.check_token()
            code = r.get('code')
            if code == CODE_OK:
                acc['last_token_check'] = t
                T['token_ok'] += 1
                if acc.get('status') in ('token_expired', 'new'):
                    acc['status'] = 'ok'
                    acc['status_msg'] = ''
                    LOG.ok('登录态校验通过', login)
            elif code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
                acc['status'] = 'token_expired'
                acc['status_msg'] = '登录态失效(%s)，请重新登录' % code
                LOG.error('登录态失效 code=%s，需要重新添加账号' % code, login)
                STORE.save()
                return False
            else:
                LOG.warn('checkToken 返回 %s %s' % (code, r.get('msg', '')), login)
                acc['last_token_check'] = t
        except Exception as e:
            LOG.warn('checkToken 异常: %s' % e, login)

    # 2) 设备扫描：刷新状态 + 关机唤醒
    if t - acc.get('last_scan', 0) >= SCAN_INTERVAL or not acc.get('devices'):
        try:
            refresh_devices(acc, api, do_wake=True)
            acc['last_scan'] = t
            if acc.get('status') in ('idle', 'error', 'new'):
                acc['status'] = 'ok'
                acc['status_msg'] = ''
        except TokenExpired:
            acc['status'] = 'token_expired'
            acc['status_msg'] = '登录态失效，请重新登录'
            STORE.save()
            LOG.error('拉取设备列表时登录态失效', login)
            return False
        except Exception as e:
            acc['status'] = 'error'
            acc['status_msg'] = '拉取设备列表失败: %s' % e
            acc['last_scan'] = t - SCAN_INTERVAL + 60   # 失败后退避 60s 再试
            failed = True
            LOG.warn('拉取设备列表失败: %s' % e, login)

    # 3) 设备在线上报（每账号一次，2min）
    if t - acc.get('last_report', 0) >= REPORT_INTERVAL:
        try:
            r = api.info_report()
            if r.get('code') == CODE_OK:
                acc['last_report'] = t
                T['reports'] += 1
            else:
                acc['last_report'] = t - REPORT_INTERVAL + 60
                LOG.warn('infoReport 返回 %s %s' % (r.get('code'), r.get('msg', '')), login)
        except Exception as e:
            acc['last_report'] = t - REPORT_INTERVAL + 60
            LOG.warn('infoReport 异常: %s' % e, login)

    # 4) 定时保活：每隔 N 分钟主动发一次连接凭证请求
    #    这是核心——在平台 24 小时计时器到期之前就主动"用一次"，把计时器重置，
    #    而不是等它关机了再去开机。
    interval_min = acc.get('keepalive_interval', DEFAULT_KEEPALIVE_INTERVAL)
    if interval_min and interval_min > 0:
        due = t - interval_min * 60
        for dev in acc.get('devices', []):
            if not dev.get('enabled'):
                continue
            if dev.get('last_auth', 0) and dev['last_auth'] > due:
                continue
            try:
                r = api.firm_auth(dev['userServiceId'])
                dev['last_auth'] = t
                dev['auth_kind'] = 'keepalive'
                dev['auth_msg'] = '[%s] %s' % (r.get('code'), r.get('msg', ''))
                if r.get('code') == CODE_OK:
                    dev['auth_count'] = dev.get('auth_count', 0) + 1
                    T['auths'] = T.get('auths', 0) + 1
                    LOG.ok('定时保活成功 [%s] %s（计时器已重置，下次 %d 分钟后）'
                           % (dev['userServiceId'], dev['vmName'], interval_min), login)
                else:
                    T['auth_err'] = T.get('auth_err', 0) + 1
                    LOG.warn('定时保活返回异常 [%s] %s: %s'
                             % (dev['userServiceId'], r.get('code'), r.get('msg', '')), login)
                STORE.save()
            except Exception as e:
                LOG.warn('定时保活失败 [%s]: %s' % (dev['userServiceId'], e), login)

    # 5) 每台启用的设备发心跳（30s）
    for dev in acc.get('devices', []):
        if not dev.get('enabled'):
            continue
        if dev.get('vmStatus') == VM_OFF and not vm_is_on(dev):
            # 已关机设备不发心跳，等待唤醒逻辑处理
            continue
        if t - dev.get('last_heartbeat', 0) < HB_INTERVAL:
            continue
        try:
            r = api.heartbeat(dev['userServiceId'])
            code = r.get('code')
            dev['last_heartbeat'] = t
            dev['hb_code'] = code
            dev['hb_msg'] = r.get('msg', '')
            if code == CODE_OK:
                T['hb_ok'] += 1
            elif code in CODE_LOCK_SCREEN:
                T['hb_ok'] += 1   # 锁屏态属正常
            elif code == CODE_OTHER_LOGIN:
                T['hb_err'] += 1
                LOG.warn('云电脑[%s] %s' % (dev['userServiceId'], r.get('msg', '')), login)
            elif code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
                acc['status'] = 'token_expired'
                acc['status_msg'] = '登录态失效，请重新登录'
                STORE.save()
                LOG.error('心跳时登录态失效', login)
                return False
            elif code in (CODE_NEED_ACTIVATE, CODE_IN_ACTIVATE, CODE_INIT_ERR):
                LOG.warn('云电脑[%s] 状态码 %s: %s' % (dev['userServiceId'], code, r.get('msg', '')), login)
            else:
                T['hb_err'] += 1
                acc['last_scan'] = 0   # 异常 → 下轮立即扫描/尝试唤醒
                LOG.warn('云电脑[%s] 心跳返回 %s: %s' % (dev['userServiceId'], code, r.get('msg', '')), login)
        except Exception as e:
            T['hb_err'] += 1
            LOG.warn('云电脑[%s] 心跳异常: %s' % (dev['userServiceId'], e), login)

    acc['last_tick'] = t
    # 熔断计数：失败累到 3 次就冷却 5 分钟；成功一次清零
    if failed:
        acc['fail_count'] = acc.get('fail_count', 0) + 1
        if acc['fail_count'] >= 3:
            acc['cooldown_until'] = t + 300
            LOG.warn('连续失败 %d 次，冷却 5 分钟后重试' % acc['fail_count'], login)
    else:
        acc['fail_count'] = 0
        acc['cooldown_until'] = 0
    STORE.save()
    return not failed


class Supervisor(threading.Thread):
    """保活主循环"""

    def __init__(self):
        super().__init__(daemon=True, name='supervisor')
        self.stop_flag = threading.Event()

    def run(self):
        if not preflight():
            LOG.error('启动自检未通过，保活引擎已停止；请修复上面的问题后重启')
            return
        LOG.info('保活引擎已启动（心跳 %ss / 上报 %ss / 登录态校验 %ss / 扫描 %ss）'
                 % (HB_INTERVAL, REPORT_INTERVAL, TOKEN_INTERVAL, SCAN_INTERVAL))
        while not self.stop_flag.is_set():
            try:
                if STORE.settings.get('global_enabled', True):
                    for acc in STORE.all():
                        ensure_defaults(acc)
                        if not acc.get('enabled'):
                            continue
                        # 到期强制停止：到点就把 enabled 关掉，不再心跳/上报/保活
                        exp = acc.get('expire_at') or 0
                        if exp and now_ts() >= exp:
                            acc['enabled'] = False
                            acc['status'] = 'expired_stopped'
                            acc['status_msg'] = '已到到期时间（%s），保活已强制停止' % fmt_ts(exp)
                            STORE.save()
                            LOG.warn('账号 %s 已到期（%s），保活已强制停止，不再续保'
                                     % (acc.get('login'), fmt_ts(exp)), acc.get('login', ''))
                            continue
                        try:
                            account_tick(acc)
                        except TokenExpired:
                            acc['status'] = 'token_expired'
                            acc['status_msg'] = '登录态失效，请重新登录'
                            STORE.save()
                        except Exception:
                            acc['status'] = 'error'
                            acc['status_msg'] = traceback.format_exc(limit=1).strip().split('\n')[-1]
                            LOG.error('账号[%s] 保活异常: %s' % (acc.get('login'), acc.get('status_msg')),
                                      acc.get('login', ''))
            except Exception as e:
                LOG.error('保活循环异常: %s' % e)
            self.stop_flag.wait(TICK)


SUPERVISOR = Supervisor()


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
PANEL_PASS = os.environ.get('CMCC_PANEL_PASS', '')
AUTH_COOKIE = 'cmcc_auth'

# 未认证时的登录页（内联，避免在公网暴露面板本体）
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>移动云电脑保活面板 · 登录</title>
<style>
 *{box-sizing:border-box}
 body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
      background:#f4f6f9;font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#1f2937}
 .box{background:#fff;border:1px solid #e3e8ef;border-radius:14px;box-shadow:0 8px 30px rgba(16,24,40,.1);
      padding:28px 30px;width:100%;max-width:340px}
 h1{font-size:17px;margin:0 0 4px;font-weight:700}
 .sub{font-size:12px;color:#6b7280;margin-bottom:18px}
 input{width:100%;padding:10px 12px;border:1px solid #e3e8ef;border-radius:8px;font-size:14px;outline:none}
 input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
 button{margin-top:12px;width:100%;padding:10px;border:0;border-radius:8px;background:#2563eb;
        color:#fff;font-size:14px;font-weight:600;cursor:pointer}
 button:hover{background:#1d4ed8}
 .err{color:#dc2626;font-size:12.5px;margin-top:10px;min-height:18px}
</style></head><body>
<div class="box">
  <h1>移动云电脑 · 保活面板</h1>
  <div class="sub">请输入面板访问密码</div>
  <form id="f"><input type="password" id="p" placeholder="访问密码" autofocus>
  <button type="submit">进入面板</button></form>
  <div class="err" id="e"></div>
</div>
<script>
var f=document.getElementById('f'),p=document.getElementById('p'),e=document.getElementById('e');
f.onsubmit=function(ev){
  ev.preventDefault();
  var v=p.value.trim();
  if(!v){ e.textContent='请输入密码'; return; }
  fetch('/api/state?token='+encodeURIComponent(v)).then(function(r){return r.json();}).then(function(d){
    if(d && d.ok){ location.href='/?token='+encodeURIComponent(v); }
    else { e.textContent='密码不正确'; p.select(); }
  }).catch(function(){ e.textContent='网络错误，请重试'; });
};
</script></body></html>
"""


def pub_account(acc):
    """输出给前端的账号视图（去掉敏感 token 全量，仅显示片段）"""
    ensure_defaults(acc)
    tok = acc.get('sohoToken') or ''
    exp = acc.get('expire_at') or 0
    now = now_ts()
    return {
        'key': acc['key'],
        'login': acc.get('login', ''),
        'login_type': acc.get('login_type', ''),
        'phone': acc.get('phone', ''),
        'username': acc.get('username', ''),
        'nickname': acc.get('nickname', ''),
        'remark': acc.get('remark', ''),
        'display': acc.get('remark') or acc.get('nickname') or acc.get('login', ''),
        'expire_at': exp,
        'expire_left': (exp - now) if exp else 0,
        'expired': bool(exp and now >= exp),
        'userId': acc.get('userId', ''),
        'isSubAccount': acc.get('isSubAccount', False),
        'enabled': acc.get('enabled', True),
        'keepalive_interval': acc.get('keepalive_interval', DEFAULT_KEEPALIVE_INTERVAL),
        'wake_on_off': acc.get('wake_on_off', True),
        'status': acc.get('status', 'idle'),
        'status_msg': acc.get('status_msg', ''),
        'token_tail': tok[-8:] if tok else '',
        'createdAt': acc.get('createdAt', 0),
        'last_token_check': acc.get('last_token_check', 0),
        'last_scan': acc.get('last_scan', 0),
        'last_report': acc.get('last_report', 0),
        'last_tick': acc.get('last_tick', 0),
        'totals': acc.get('totals', {}),
        'devices': [{
            'userServiceId': d.get('userServiceId'),
            'vmName': d.get('vmName', ''),
            'skuName': d.get('skuName', ''),
            'skuSpecStr': d.get('skuSpecStr', ''),
            'vmStatus': d.get('vmStatus'),
            'vmStatusShow': d.get('vmStatusShow', ''),
            'enabled': d.get('enabled', True),
            'last_heartbeat': d.get('last_heartbeat', 0),
            'hb_code': d.get('hb_code'),
            'hb_msg': d.get('hb_msg', ''),
            'last_wake': d.get('last_wake', 0),
            'wake_count': d.get('wake_count', 0),
            'last_auth': d.get('last_auth', 0),
            'auth_count': d.get('auth_count', 0),
            'auth_kind': d.get('auth_kind', ''),
            'auth_msg': d.get('auth_msg', ''),
        } for d in acc.get('devices', [])],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = 'cmcc-keepalive/1.0'

    # ---- 基础 ----
    def log_message(self, fmt, *args):
        pass  # 静默，防止刷屏

    def _send(self, code, body, ctype='application/json; charset=utf-8', extra_headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        elif isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, obj)

    def _read_json(self):
        try:
            ln = int(self.headers.get('Content-Length') or 0)
            if ln <= 0:
                return {}
            return json.loads(self.rfile.read(ln).decode('utf-8'))
        except Exception:
            return {}

    # ---- 鉴权 ----
    def _authed(self, q):
        if not PANEL_PASS:
            return True
        if q.get('token', [None])[0] == PANEL_PASS:
            return True
        cookie = self.headers.get('Cookie') or ''
        for part in cookie.split(';'):
            k, _, v = part.strip().partition('=')
            if k == AUTH_COOKIE and v == PANEL_PASS:
                return True
        return False

    def _need_auth(self, q):
        if self._authed(q):
            return False
        if q.get('token', [None])[0] == PANEL_PASS:
            return False
        self._json({'ok': False, 'error': 'unauthorized'}, 401)
        return True

    # ---- GET ----
    def do_GET(self):
        try:
            self._do_get()
        except Exception as e:
            LOG.error('GET %s 处理异常: %s' % (self.path, e))
            try:
                self._json({'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}, 500)
            except Exception:
                pass

    def _do_get(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path

        if path in ('/', '/index.html'):
            if PANEL_PASS and not self._authed(q):
                # 未认证：只给登录页，不暴露面板本体
                self._send(200, LOGIN_PAGE.encode('utf-8'), 'text/html; charset=utf-8')
                return
            try:
                with open(PANEL_FILE, 'rb') as f:
                    page = f.read()
            except Exception:
                self._send(500, 'panel.html missing', 'text/plain; charset=utf-8')
                return
            headers = {}
            if PANEL_PASS and q.get('token', [None])[0] == PANEL_PASS:
                headers['Set-Cookie'] = '%s=%s; Path=/; Max-Age=2592000; SameSite=Lax' % (AUTH_COOKIE, PANEL_PASS)
            self._send(200, page, 'text/html; charset=utf-8', headers)
            return

        if self._need_auth(q):
            return

        if path == '/api/state':
            accs = [pub_account(a) for a in STORE.all()]
            self._json({
                'ok': True,
                'time': now_ts(),
                'settings': STORE.settings,
                'supervisor_alive': SUPERVISOR.is_alive(),
                'intervals': {'hb': HB_INTERVAL, 'report': REPORT_INTERVAL,
                              'token': TOKEN_INTERVAL, 'scan': SCAN_INTERVAL},
                'accounts': accs,
            })
            return

        if path == '/api/logs':
            since = int(q.get('since', ['0'])[0] or 0)
            items = LOG.since(since)
            self._json({'ok': True, 'logs': items, 'seq': LOG.seq})
            return

        if path == '/api/captcha':
            login = (q.get('login', [''])[0] or '').strip()
            if not login:
                self._json({'ok': False, 'error': '缺少账号'})
                return
            try:
                s = temp_session(login)
                r = s['api'].get_captcha()
                if r.get('code') == CODE_OK and r.get('data'):
                    s['randomCode'] = r['data'].get('randomCode', '')
                    self._json({'ok': True,
                                'img': r['data'].get('verificationCode', ''),
                                'randomCode': s['randomCode']})
                else:
                    self._json({'ok': False, 'error': '%s %s' % (r.get('code'), r.get('msg'))})
            except Exception as e:
                self._json({'ok': False, 'error': str(e)})
            return

        if path == '/api/qrlogin/poll':
            sid = (q.get('sid', [''])[0] or '').strip()
            s = TEMP_SESSIONS.get(sid)
            if not s:
                self._json({'ok': False, 'error': '会话已过期，请刷新二维码', 'expired': True})
                return
            try:
                r = s['api'].check_login_status(s.get('qr_token', ''))
                code = r.get('code')
                if code == CODE_OK and r.get('data'):
                    data = r['data']
                    login = data.get('phone') or data.get('username') or ('uid_' + str(data.get('userId')))
                    acc, created = STORE.add_or_update(
                        login=login, login_type='qr',
                        token_data={**data, 'phone': data.get('phone') or ''},
                        device=s['api'].device,
                    )
                    try:
                        s['api'].collect_info()
                        refresh_devices(acc, s['api'], do_wake=True)
                        acc['last_scan'] = now_ts()
                        acc['status'] = 'ok'
                        acc['status_msg'] = ''
                    except Exception as e:
                        acc['status'] = 'error'
                        acc['status_msg'] = '初始化失败: %s' % e
                    STORE.save()
                    TEMP_SESSIONS.pop(sid, None)
                    LOG.ok('扫码登录成功：%s，设备 %d 台' % (login, len(acc.get('devices', []))))
                    self._json({'ok': True, 'status': 'success', 'login': login,
                                'devices': len(acc.get('devices', []))})
                elif code == CODE_SCANING:
                    self._json({'ok': True, 'status': 'scaning', 'msg': r.get('msg', '已扫码，请在手机上确认')})
                elif code == CODE_QRCODE_EXPIRED:
                    TEMP_SESSIONS.pop(sid, None)
                    self._json({'ok': True, 'status': 'expired', 'msg': '二维码已失效，请刷新'})
                else:
                    self._json({'ok': True, 'status': 'pending', 'code': code, 'msg': r.get('msg', '')})
            except Exception as e:
                self._json({'ok': False, 'error': str(e)})
            return

        if path == '/api/check':
            # 供部署后自检
            self._json({'ok': True, 'service': 'cmcc-keepalive', 'time': now_ts()})
            return

        self._json({'ok': False, 'error': 'not found'}, 404)

    # ---- POST ----
    def do_POST(self):
        try:
            self._do_post()
        except Exception as e:
            LOG.error('POST %s 处理异常: %s' % (self.path, e))
            try:
                self._json({'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}, 500)
            except Exception:
                pass

    def _do_post(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        if self._need_auth(q):
            return
        body = self._read_json()

        try:
            if path == '/api/qrlogin/start':
                self._api_qrlogin_start(body)
            elif path == '/api/sms/send':
                self._api_sms_send(body)
            elif path == '/api/account/sms':
                self._api_account_sms(body)
            elif path == '/api/account/pwd':
                self._api_account_pwd(body)
            elif path == '/api/account/remove':
                self._api_account_remove(body)
            elif path == '/api/account/toggle':
                self._api_account_toggle(body)
            elif path == '/api/account/refresh':
                self._api_account_refresh(body)
            elif path == '/api/account/wake':
                self._api_account_wake(body)
            elif path == '/api/device/toggle':
                self._api_device_toggle(body)
            elif path == '/api/settings':
                self._api_settings(body)
            elif path == '/api/account/relogin':
                self._api_account_relogin(body)
            elif path == '/api/account/import':
                self._api_account_import(body)
            elif path == '/api/account/keepalive':
                self._api_account_keepalive(body)
            elif path == '/api/account/update':
                self._api_account_update(body)
            elif path == '/api/account/start':
                self._api_account_start(body)
            elif path == '/api/account/stop':
                self._api_account_stop(body)
            elif path == '/api/account/check':
                self._api_account_check(body)
            elif path == '/api/account/keepalive_now':
                self._api_account_keepalive_now(body)
            else:
                self._json({'ok': False, 'error': 'not found'}, 404)
        except Exception as e:
            self._json({'ok': False, 'error': '%s: %s' % (type(e).__name__, e)})

    # ---- API 实现 ----
    def _api_qrlogin_start(self, body):
        """扫码登录：取二维码（sid 由前端持有，用于后续轮询）"""
        sid = 'qr_' + secrets.token_hex(6)
        try:
            s = temp_session(sid)
            r = s['api'].get_lg_token_url()
            if r.get('code') != CODE_OK or not r.get('data'):
                self._json({'ok': False, 'error': '[%s] %s' % (r.get('code'), r.get('msg', '取码失败'))})
                return
            url = r['data'].get('url') or ''
            s['qr_token'] = r['data'].get('token') or ''
            if not url:
                self._json({'ok': False, 'error': '服务端未返回二维码内容'})
                return
            png, ver = make_qr_png(url, scale=8, border=4)
            img = 'data:image/png;base64,' + base64.b64encode(png).decode()
            s['img'] = img
            LOG.info('已生成扫码登录二维码（QR v%s，%d 字符）' % (ver, len(url)))
            self._json({'ok': True, 'sid': sid, 'img': img, 'url': url})
        except Exception as e:
            LOG.error('生成二维码失败: %s' % e)
            self._json({'ok': False, 'error': str(e)})

    def _api_sms_send(self, body):
        phone = (body.get('phone') or '').strip()
        if not re.fullmatch(r'1\d{10}', phone):
            self._json({'ok': False, 'error': '手机号格式不正确'})
            return
        try:
            s = temp_session(phone)
            r = s['api'].send_sms(phone)
            if r.get('code') == CODE_OK:
                LOG.info('已向 %s 发送短信验证码' % phone[:3] + '****' + phone[-4:])
                self._json({'ok': True})
            else:
                self._json({'ok': False, 'error': '[%s] %s' % (r.get('code'), r.get('msg', '发送失败'))})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)})

    def _api_account_sms(self, body):
        phone = (body.get('phone') or '').strip()
        code = (body.get('code') or '').strip()
        if not phone or not code:
            self._json({'ok': False, 'error': '缺少手机号或验证码'})
            return
        s = temp_session(phone)
        api = s['api']
        r = api.sms_login(phone, code)
        if r.get('code') != CODE_OK or not r.get('data'):
            self._json({'ok': False, 'error': '[%s] %s' % (r.get('code'), r.get('msg', '登录失败'))})
            return
        data = r['data']
        acc, created = STORE.add_or_update(
            login=phone, login_type='sms',
            token_data={**data, 'phone': data.get('phone') or phone},
            device=api.device,
        )
        # 登录后立刻做首轮初始化
        try:
            api.collect_info()
            refresh_devices(acc, api, do_wake=True)
            acc['last_scan'] = now_ts()
            acc['status'] = 'ok'
        except Exception as e:
            acc['status'] = 'error'
            acc['status_msg'] = '初始化失败: %s' % e
        STORE.save()
        POOL.drop(acc['key'])
        LOG.ok('%s账号 %s，设备 %d 台' % ('新增' if created else '更新', phone, len(acc.get('devices', []))))
        self._json({'ok': True, 'key': acc['key'], 'created': created})

    def _api_account_pwd(self, body):
        username = (body.get('username') or '').strip()
        password = body.get('password') or ''
        vcode = (body.get('vcode') or '').strip()
        if not username or not password:
            self._json({'ok': False, 'error': '缺少账号或密码'})
            return
        s = temp_session(username)
        api = s['api']
        rcode = s.get('randomCode', '')
        r = api.pwd_login(username, password, vcode, rcode)
        if r.get('code') != CODE_OK or not r.get('data'):
            need_vc = (r.get('code') == CODE_NEED_VC) or ('验证码' in (r.get('msg') or ''))
            self._json({'ok': False, 'need_vcode': need_vc,
                        'error': '[%s] %s' % (r.get('code'), r.get('msg', '登录失败'))})
            return
        data = r['data']
        acc, created = STORE.add_or_update(
            login=username, login_type='pwd',
            token_data={**data, 'username': data.get('username') or username},
            device=api.device,
        )
        try:
            api.collect_info()
            refresh_devices(acc, api, do_wake=True)
            acc['last_scan'] = now_ts()
            acc['status'] = 'ok'
        except Exception as e:
            acc['status'] = 'error'
            acc['status_msg'] = '初始化失败: %s' % e
        STORE.save()
        POOL.drop(acc['key'])
        LOG.ok('%s账号 %s，设备 %d 台' % ('新增' if created else '更新', username, len(acc.get('devices', []))))
        self._json({'ok': True, 'key': acc['key'], 'created': created})

    def _api_account_import(self, body):
        """用已有 sohoToken 直接导入账号（免登录）。

        body: {userId, sohoToken, login(手机号/用户名), deviceId?}
        适合从本机客户端 config.json 或抓包里取得的会话。
        """
        user_id = str(body.get('userId') or '').strip()
        token = (body.get('sohoToken') or '').strip()
        login = (body.get('login') or '').strip()
        device_id = (body.get('deviceId') or '').strip()
        if not user_id or not token:
            self._json({'ok': False, 'error': '缺少 userId 或 sohoToken'})
            return
        device = make_device_profile(device_id) if device_id else None
        api = CMCCApi(device=device, soho_token=token, user_id=user_id, timeout=15)
        try:
            r = api.check_token()
        except Exception as e:
            self._json({'ok': False, 'error': '校验 token 失败: %s' % e})
            return
        if r.get('code') in CODE_UNTOKEN or r.get('code') == CODE_H5_LOGINED:
            self._json({'ok': False, 'error': 'token 已失效，请用短信/密码重新登录'})
            return
        if r.get('code') != CODE_OK:
            self._json({'ok': False, 'error': '[%s] %s' % (r.get('code'), r.get('msg', '校验失败'))})
            return
        acc, created = STORE.add_or_update(
            login=login or ('uid_' + user_id), login_type='import',
            token_data={'userId': user_id, 'sohoToken': token, 'phone': login if login else ''},
            device=device or api.device,
        )
        try:
            api.collect_info()
            refresh_devices(acc, api, do_wake=True)
            acc['last_scan'] = now_ts()
            acc['last_token_check'] = now_ts()
            acc['status'] = 'ok'
            acc['status_msg'] = ''
        except Exception as e:
            acc['status'] = 'error'
            acc['status_msg'] = '初始化失败: %s' % e
        STORE.save()
        POOL.drop(acc['key'])
        LOG.ok('%s导入账号 %s，设备 %d 台' % ('新增' if created else '更新', acc['login'], len(acc.get('devices', []))))
        self._json({'ok': True, 'key': acc['key'], 'created': created,
                    'devices': len(acc.get('devices', []))})

    def _api_account_keepalive(self, body):
        """设置定时保活策略：{key, interval(分钟), wake_on_off}"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        if 'interval' in body:
            try:
                interval = int(body.get('interval'))
            except (TypeError, ValueError):
                self._json({'ok': False, 'error': '间隔必须是整数分钟'})
                return
            if interval < 0 or interval > MAX_KEEPALIVE_MIN:
                self._json({'ok': False, 'error': '间隔范围 0-%d 分钟（0=关闭定时保活）' % MAX_KEEPALIVE_MIN})
                return
            acc['keepalive_interval'] = interval
        if 'wake_on_off' in body:
            acc['wake_on_off'] = bool(body.get('wake_on_off'))
        # 改小间隔时立即生效：把上次保活时间往前推，让下轮就触发
        if acc.get('keepalive_interval'):
            for dev in acc.get('devices', []):
                if not dev.get('last_auth'):
                    continue
                if now_ts() - dev['last_auth'] >= acc['keepalive_interval'] * 60:
                    dev['last_auth'] = 0
        STORE.save()
        LOG.info('账号 %s 定时保活间隔=%s 分钟，关机唤醒=%s'
                 % (acc.get('login'), acc.get('keepalive_interval'), acc.get('wake_on_off')))
        self._json({'ok': True, 'interval': acc.get('keepalive_interval'),
                    'wake_on_off': acc.get('wake_on_off')})

    def _api_account_update(self, body):
        """统一设置入口（对应面板「修改设置」）
        body: {key, remark?, expire_at?, interval_hours? | interval_min?, wake_on_off?}
        """
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        ensure_defaults(acc)
        changed = []

        if 'remark' in body:
            acc['remark'] = str(body.get('remark') or '').strip()[:32]
            changed.append('备注=%s' % (acc['remark'] or '(空)'))

        if 'expire_at' in body:
            ts = parse_expire(body.get('expire_at'))
            if ts is None:
                self._json({'ok': False, 'error': '到期时间格式不正确，请用 2026-10-09 18:00 这种格式'})
                return
            acc['expire_at'] = ts
            changed.append('到期=%s' % (fmt_ts(ts) if ts else '不限期'))

        if 'interval_hours' in body or 'interval_min' in body:
            try:
                if 'interval_min' in body:
                    mins = int(round(float(body.get('interval_min'))))
                else:
                    mins = int(round(float(body.get('interval_hours')) * 60))
            except (TypeError, ValueError):
                self._json({'ok': False, 'error': '间隔必须是数字'})
                return
            if mins < 0 or mins > MAX_KEEPALIVE_MIN:
                self._json({'ok': False, 'error': '间隔范围 0 - %d 分钟（最长 %d 天）'
                                                  % (MAX_KEEPALIVE_MIN, MAX_KEEPALIVE_MIN // 1440)})
                return
            acc['keepalive_interval'] = mins
            changed.append('间隔=%s' % ((('%g 小时' % (mins / 60.0)) if mins else '关闭定时保活')))

        if 'wake_on_off' in body:
            acc['wake_on_off'] = bool(body.get('wake_on_off'))
            changed.append('关机唤醒=%s' % ('开' if acc['wake_on_off'] else '关'))

        # 间隔改小后立即生效：把已超期设备的 last_auth 归零，让下一轮就触发保活
        iv = acc.get('keepalive_interval') or 0
        if iv > 0:
            for dev in acc.get('devices', []):
                if now_ts() - dev.get('last_auth', 0) >= iv * 60:
                    dev['last_auth'] = 0
        STORE.save()
        LOG.info('账号 %s 设置已更新：%s' % (acc.get('login'), '，'.join(changed) or '(无变化)'),
                 acc.get('login'))
        self._json({'ok': True, 'remark': acc.get('remark', ''),
                    'expire_at': acc.get('expire_at', 0),
                    'interval': acc.get('keepalive_interval'),
                    'wake_on_off': acc.get('wake_on_off', True)})

    def _api_account_start(self, body):
        """启动保活：清零计时，下一轮立即做登录态校验 + 定时保活"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        ensure_defaults(acc)
        exp = acc.get('expire_at') or 0
        if exp and now_ts() >= exp:
            self._json({'ok': False,
                        'error': '该账号已过到期时间（%s），请先在「修改设置」里更新或清空到期时间'
                                 % fmt_ts(exp)})
            return
        acc['enabled'] = True
        acc['status'] = 'ok'
        acc['status_msg'] = ''
        acc['fail_count'] = 0
        acc['cooldown_until'] = 0
        acc['last_token_check'] = 0     # 立即做一次登录态校验
        acc['last_scan'] = 0            # 立即刷新设备
        acc['last_report'] = 0          # 立即在线上报
        for dev in acc.get('devices', []):
            dev['last_auth'] = 0        # 启动后立刻保活一次
            dev['last_heartbeat'] = 0
        STORE.save()
        LOG.ok('账号 %s 保活已启动' % acc.get('login'), acc.get('login'))
        self._json({'ok': True})

    def _api_account_stop(self, body):
        """停止保活：立即停止心跳/上报/定时保活，保留账号与设置"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        ensure_defaults(acc)
        acc['enabled'] = False
        acc['status'] = 'stopped'
        acc['status_msg'] = '已手动停止保活'
        STORE.save()
        LOG.warn('账号 %s 保活已停止（手动）' % acc.get('login'), acc.get('login'))
        self._json({'ok': True})

    def _api_account_check(self, body):
        """检测是否还在线：checkToken + 设备列表 + 首台设备心跳实测。
        密码被改 / 在别处登录 / 会话被顶 → 这里会直接报「不在线」。"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        ensure_defaults(acc)
        api = POOL.get(acc)
        detail = []
        online = None

        # 1) 登录态校验
        try:
            r = api.check_token()
            code = r.get('code')
            detail.append({'step': 'checkToken', 'code': code, 'msg': r.get('msg', '')})
            if code == CODE_OK:
                online = True
                acc['last_token_check'] = now_ts()
                STORE.totals(acc)['token_ok'] += 1
            elif code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
                online = False
        except Exception as e:
            detail.append({'step': 'checkToken', 'code': -1, 'msg': str(e)})

        devs = []
        if online is not False:
            # 2) 拉设备列表（顺带刷新面板数据，不触发唤醒）
            try:
                devs = [d for d in refresh_devices(acc, api, do_wake=False) if d.get('enabled')]
                acc['last_scan'] = now_ts()
            except TokenExpired:
                online = False
                detail.append({'step': 'listCloudPcs', 'code': CODE_UNTOKEN[0], 'msg': '登录态失效'})
            except Exception as e:
                detail.append({'step': 'listCloudPcs', 'code': -1, 'msg': str(e)})

        # 3) 首台设备心跳实测（最能反映"云电脑是否还认这个会话"）
        if online is not False and devs:
            d0 = devs[0]
            try:
                r = api.heartbeat(d0['userServiceId'])
                code = r.get('code')
                d0['last_heartbeat'] = now_ts()
                d0['hb_code'] = code
                d0['hb_msg'] = r.get('msg', '')
                detail.append({'step': 'heartbeat', 'code': code, 'msg': r.get('msg', '')})
                if code == CODE_OK or code in CODE_LOCK_SCREEN:
                    online = True
                elif code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
                    online = False
            except Exception as e:
                detail.append({'step': 'heartbeat', 'code': -1, 'msg': str(e)})

        # 4) 结论落库
        if online is True:
            if acc.get('status') in ('token_expired', 'error'):
                acc['status'] = 'ok' if acc.get('enabled') else 'stopped'
                acc['status_msg'] = ''
            acc['fail_count'] = 0
            acc['cooldown_until'] = 0
            LOG.ok('在线检测：正常，%d 台云电脑可保活' % len(acc.get('devices', [])), acc.get('login'))
        elif online is False:
            acc['status'] = 'token_expired'
            acc['status_msg'] = '在线检测不通过：登录态失效，请重新登录'
            LOG.error('在线检测：登录态已失效，保活无法继续（改过密码 / 在别处登录 / 会话被顶）',
                      acc.get('login'))
        else:
            LOG.warn('在线检测：网络异常，暂无法判定（%s）'
                     % json.dumps(detail, ensure_ascii=False)[:160], acc.get('login'))
        STORE.save()
        self._json({'ok': True, 'online': online, 'detail': detail,
                    'status': acc.get('status'), 'devices': len(acc.get('devices', [])),
                    'time': now_ts()})

    def _api_account_keepalive_now(self, body):
        """立即执行一次保活（对所有启用设备发 getFirmAuth），忽略间隔计时"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        ensure_defaults(acc)
        if not acc.get('devices'):
            self._json({'ok': False, 'error': '还没有云电脑列表，请先点「检测在线」或「刷新设备」'})
            return
        api = POOL.get(acc)
        results = []
        ok_n = err_n = 0
        for dev in acc.get('devices', []):
            if not dev.get('enabled'):
                continue
            sid = dev.get('userServiceId')
            try:
                r = api.firm_auth(sid)
                code = r.get('code')
                dev['last_auth'] = now_ts()
                dev['auth_kind'] = 'manual'
                dev['auth_msg'] = '[%s] %s' % (code, r.get('msg', ''))
                if code == CODE_OK:
                    dev['auth_count'] = dev.get('auth_count', 0) + 1
                    STORE.totals(acc)['auths'] += 1
                    ok_n += 1
                else:
                    err_n += 1
                    STORE.totals(acc)['auth_err'] += 1
                    if code in CODE_UNTOKEN or code == CODE_H5_LOGINED:
                        acc['status'] = 'token_expired'
                        acc['status_msg'] = '登录态失效，请重新登录'
                results.append({'sid': sid, 'code': code, 'msg': r.get('msg', '')})
            except Exception as e:
                err_n += 1
                results.append({'sid': sid, 'code': -1, 'msg': str(e)})
        STORE.save()
        if ok_n and not err_n:
            LOG.ok('已立即执行一次保活：%d 台成功（计时器已重置）' % ok_n, acc.get('login'))
        elif ok_n:
            LOG.warn('立即保活：成功 %d 台 / 失败 %d 台' % (ok_n, err_n), acc.get('login'))
        else:
            LOG.warn('立即保活未成功：%s' % json.dumps(results, ensure_ascii=False)[:200], acc.get('login'))
        self._json({'ok': err_n == 0, 'ok_count': ok_n, 'err_count': err_n, 'results': results})

    def _api_account_relogin(self, body):
        """传 key + 短信验证码，为已有账号重新登录刷新 token"""
        key = body.get('key') or ''
        code = (body.get('code') or '').strip()
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        phone = acc.get('login') if acc.get('login_type') == 'sms' else acc.get('phone')
        if not phone:
            self._json({'ok': False, 'error': '该账号无法短信重登，请删除后重新添加'})
            return
        s = temp_session(phone)
        r = s['api'].sms_login(phone, code)
        if r.get('code') != CODE_OK or not r.get('data'):
            self._json({'ok': False, 'error': '[%s] %s' % (r.get('code'), r.get('msg', '登录失败'))})
            return
        acc['sohoToken'] = r['data'].get('sohoToken') or acc['sohoToken']
        acc['userId'] = str(r['data'].get('userId') or acc['userId'])
        acc['status'] = 'ok'
        acc['status_msg'] = ''
        acc['last_token_check'] = 0
        STORE.save()
        POOL.drop(key)
        LOG.ok('账号 %s 已重新登录' % acc.get('login'))
        self._json({'ok': True})

    def _api_account_remove(self, body):
        key = body.get('key') or ''
        acc = STORE.remove(key)
        POOL.drop(key)
        if acc:
            LOG.warn('已删除账号 %s' % acc.get('login'))
        self._json({'ok': True})

    def _api_account_toggle(self, body):
        """兼容旧接口：等价于 /start 或 /stop"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        if body.get('enabled'):
            self._api_account_start(body)
        else:
            self._api_account_stop(body)

    def _api_account_refresh(self, body):
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        api = POOL.get(acc)
        try:
            devs = refresh_devices(acc, api, do_wake=True)
            acc['last_scan'] = now_ts()
            if acc.get('status') in ('error', 'idle'):
                acc['status'] = 'ok'
                acc['status_msg'] = ''
            STORE.save()
            LOG.ok('已刷新设备列表：%d 台' % len(devs))
            self._json({'ok': True, 'count': len(devs)})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)})

    def _api_account_wake(self, body):
        """手动触发唤醒：对每台启用设备调 getFirmAuth"""
        key = body.get('key') or ''
        acc = STORE.get(key)
        if not acc:
            self._json({'ok': False, 'error': '账号不存在'})
            return
        api = POOL.get(acc)
        results = []
        for dev in acc.get('devices', []):
            if not dev.get('enabled'):
                continue
            try:
                r = api.firm_auth(dev['userServiceId'])
                dev['last_auth'] = now_ts()
                dev['auth_msg'] = '[%s] %s' % (r.get('code'), r.get('msg', ''))
                if r.get('code') == CODE_OK:
                    dev['last_wake'] = now_ts()
                    dev['wake_count'] = dev.get('wake_count', 0) + 1
                results.append({'sid': dev['userServiceId'], 'code': r.get('code'), 'msg': r.get('msg', '')})
            except Exception as e:
                results.append({'sid': dev.get('userServiceId'), 'code': -1, 'msg': str(e)})
        STORE.save()
        LOG.info('手动唤醒完成: %s' % json.dumps(results, ensure_ascii=False)[:300], acc.get('login'))
        self._json({'ok': True, 'results': results})

    def _api_device_toggle(self, body):
        key = body.get('key') or ''
        sid = body.get('sid')
        enabled = bool(body.get('enabled'))
        dev = STORE.device_of(key, sid)
        if not dev:
            self._json({'ok': False, 'error': '设备不存在'})
            return
        dev['enabled'] = enabled
        STORE.save()
        LOG.info('设备 [%s] 保活已%s' % (sid, '开启' if enabled else '暂停'))
        self._json({'ok': True})

    def _api_settings(self, body):
        if 'global_enabled' in body:
            STORE.settings['global_enabled'] = bool(body['global_enabled'])
            STORE.save()
            LOG.info('全局保活已%s' % ('开启' if STORE.settings['global_enabled'] else '暂停'))
        self._json({'ok': True, 'settings': STORE.settings})


def cli_import_local():
    """从本机客户端 config.json 导入会话（Windows: %APPDATA%\\CMCC-JTYDN\\config.json）"""
    path = os.environ.get('CMCC_CLIENT_CONFIG') or os.path.join(
        os.environ.get('APPDATA', ''), 'CMCC-JTYDN', 'config.json')
    if not os.path.exists(path):
        print('[导入] 未找到客户端配置: %s' % path)
        print('[导入] 可用 --import-token <userId> <sohoToken> [login] 手动导入')
        return 1
    with open(path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    user_id = str(cfg.get('userId') or '')
    token = cfg.get('sohoToken') or ''
    if not user_id or not token:
        print('[导入] config.json 中缺少 userId/sohoToken（客户端可能未登录）')
        return 1
    # 关键：token 与设备指纹绑定，必须沿用原 deviceId / appType / romVersion
    device = {
        'deviceId': cfg.get('deviceId') or make_device_profile()['deviceId'],
        'appType': cfg.get('appType') or make_device_profile()['appType'],
        'romVersion': cfg.get('romVersion') or '',
        'model': cfg.get('model') or '',
    }
    api = CMCCApi(device=device, soho_token=token, user_id=user_id, timeout=15)
    r = api.check_token()
    if r.get('code') != CODE_OK:
        print('[导入] token 校验失败: [%s] %s' % (r.get('code'), r.get('msg')))
        return 1
    login = cfg.get('phone') or cfg.get('username') or ('uid_' + user_id)
    acc, created = STORE.add_or_update(
        login=login, login_type='import',
        token_data={'userId': user_id, 'sohoToken': token, 'phone': cfg.get('phone') or ''},
        device=api.device,
    )
    api.collect_info()
    devs = refresh_devices(acc, api, do_wake=True)
    acc['last_scan'] = now_ts()
    acc['last_token_check'] = now_ts()
    acc['status'] = 'ok'
    acc['status_msg'] = ''
    STORE.save()
    print('[导入] %s账号 %s，云电脑 %d 台:' % ('新增' if created else '更新', login, len(devs)))
    for d in devs:
        print('        [%s] %s (%s)' % (d['userServiceId'], d['vmName'], d.get('vmStatusShow')))
    return 0


def cli_import_token(argv):
    """--import-token <userId> <sohoToken> [login]"""
    if len(argv) < 2:
        print('用法: python server.py --import-token <userId> <sohoToken> [login]')
        return 1
    user_id, token = argv[0], argv[1]
    login = argv[2] if len(argv) > 2 else ('uid_' + user_id)
    api = CMCCApi(device=make_device_profile(), soho_token=token, user_id=user_id, timeout=15)
    r = api.check_token()
    if r.get('code') != CODE_OK:
        print('[导入] token 校验失败: [%s] %s' % (r.get('code'), r.get('msg')))
        return 1
    acc, created = STORE.add_or_update(
        login=login, login_type='import',
        token_data={'userId': user_id, 'sohoToken': token, 'phone': ''},
        device=api.device,
    )
    api.collect_info()
    devs = refresh_devices(acc, api, do_wake=True)
    acc['last_scan'] = now_ts()
    acc['last_token_check'] = now_ts()
    acc['status'] = 'ok'
    STORE.save()
    print('[导入] %s账号 %s，云电脑 %d 台:' % ('新增' if created else '更新', login, len(devs)))
    for d in devs:
        print('        [%s] %s (%s)' % (d['userServiceId'], d['vmName'], d.get('vmStatusShow')))
    return 0


def preflight():
    """启动自检：把环境异常直接写进面板日志，避免换服务器后"默默不工作" """
    v = sys.version_info
    if (v.major, v.minor) < (3, 9):
        LOG.error('Python 版本过低 (%d.%d)，请升级到 3.9+（qrcodegen 需要）' % (v.major, v.minor))
        return False
    if not os.path.exists(PANEL_FILE):
        LOG.error('缺少面板文件 panel.html，Web 面板无法打开')
        return False
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception as e:
        LOG.error('data 目录不可写: %s' % e)
        return False
    LOG.info('Python %d.%d.%d · 平台 %s' % (v.major, v.minor, v.micro, sys.platform))
    if os.environ.get('CMCC_INSECURE', '0') == '1':
        LOG.warn('已开启 CMCC_INSECURE：跳过 SSL 证书校验（仅应急，建议修复 CA 后关闭）')
    if os.environ.get('CMCC_USE_PROXY', '0') == '1':
        LOG.info('已设置 CMCC_USE_PROXY=1：优先走系统代理')
    return True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--import-local':
        sys.exit(cli_import_local())
    if len(sys.argv) > 1 and sys.argv[1] == '--import-token':
        sys.exit(cli_import_token(sys.argv[2:]))

    ap = argparse.ArgumentParser(description='CMCC 云电脑保活服务端')
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=int(os.environ.get('CMCC_PORT', '8765')))
    args = ap.parse_args()

    SUPERVISOR.start()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    banner = '[CMCC 保活] Web 面板已启动:  http://%s:%d/' % (
        '127.0.0.1' if args.host in ('0.0.0.0', '') else args.host, args.port)
    print(banner)
    if PANEL_PASS:
        print('[CMCC 保活] 已启用面板密码（环境变量 CMCC_PANEL_PASS）')
    else:
        print('[CMCC 保活] 未设置面板密码。公网部署请设置环境变量 CMCC_PANEL_PASS 或使用反向代理加 HTTPS')
    LOG.info(banner)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SUPERVISOR.stop_flag.set()


if __name__ == '__main__':
    main()
