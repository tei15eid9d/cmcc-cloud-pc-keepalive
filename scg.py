# -*- coding: utf-8 -*-
"""
SCG（深信服）线路 · 真开机与保活
================================
背景：云电脑"自动关机计时器"按**桌面连接活动**重置，不是按心跳 API 重置。
旧的 firm_auth/heartbeat 只是控制面请求，连 10800 端口的桌面会话从没建立过，
所以机器照样到点关机。

本模块实现 CEM 开机链（纯标准库）：
    firm_auth (新 scAuthCode)
      -> exchange_cem_access_token   POST api.soho.komect.com:1443 /gzs/auth/oauth/token
      -> getConnectInfo              触发 SCG VM 开机（实测 10 秒内变"运行中"）
      -> getVmReadyStatus 轮询       未就绪时等待，返回刷新后的 scAuthCode

注意：scAuthCode 是**一次性**的，每次开机/保活都必须先重新 firm_auth 取新码。

SPICE 长连接保活：委托给 1936-zero/cmcc-cloud-alive（MIT）的 scg_route，
    通过 CMCC_ALIVE_PATH 环境变量或默认路径 /opt/cmcc-alive 查找；
    找不到则降级为"每次保活触发一次 getConnectInfo"（仍是连接事件，优于纯心跳）。

协议常量与流程取自 https://github.com/1936-zero/cmcc-cloud-alive (MIT License)。
"""
import base64
import json
import os
import secrets
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmcc_api import parse_pubkey  # noqa: E402

CEM_BASE = 'https://api.soho.komect.com:1443'
CEM_CLIENT_ID = 'sc-user-5e38ece5'
CEM_BIZ_CODE = '10002'
CEM_RSA_PUBLIC_KEY_B64 = (
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRwADvpa+s20CapaSeDeWA'
    'fRKbK5zD91jIUxNDe/2twuvKdQA+Ln3VWFtL8opVod0ebqQanpVb/uITI56G'
    'coVdSzis2IgqIkVvN+iOPH+on/FK+6EXYeIZn3MYmVxsmS0IVifVl2EGLeOC'
    'RMwjPmy9fHB+gByQtGnxAsknwBKUqQIDAQAB'
)

# 不走系统代理（服务器上可能有 clash/gost 之类）
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _rsa_pkcs1_v15_encrypt_b64(text, public_key_b64):
    """PKCS#1 v1.5: EM = 0x00 || 0x02 || PS(非零随机) || 0x00 || M"""
    n, e = parse_pubkey(public_key_b64)
    key_len = (n.bit_length() + 7) // 8
    raw = str(text).encode('utf-8')
    if len(raw) > key_len - 11:
        raise ValueError('RSA 明文过长 (%d > %d)' % (len(raw), key_len - 11))
    ps = bytearray()
    while len(ps) < key_len - len(raw) - 3:
        b = secrets.token_bytes(1)
        if b != b'\x00':
            ps += b
    em = b'\x00\x02' + bytes(ps) + b'\x00' + raw
    c = pow(int.from_bytes(em, 'big'), e, n)
    return base64.b64encode(c.to_bytes(key_len, 'big')).decode('ascii')


def _cem_rsa_encrypt(text):
    return '{rsa}' + _rsa_pkcs1_v15_encrypt_b64(text, CEM_RSA_PUBLIC_KEY_B64)


def exchange_cem_access_token(sc_auth_code, timeout=30.0):
    """scAuthCode -> CEM access_token"""
    if not sc_auth_code:
        raise ValueError('scAuthCode 为空')
    form = urllib.parse.urlencode({
        'bizCode': CEM_BIZ_CODE,
        'client_id': CEM_CLIENT_ID,
        'grant_type': 'ext',
        'source': 'biz',
        'token': sc_auth_code,
    }).encode('utf-8')
    req = urllib.request.Request(CEM_BASE + '/gzs/auth/oauth/token', data=form, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    with _NO_PROXY_OPENER.open(req, timeout=timeout) as res:
        result = json.loads(res.read().decode('utf-8', 'replace'))
    if result.get('code') != '00000':
        raise RuntimeError('oauth/token code=%s msg=%s' % (result.get('code'), result.get('msg')))
    token = (result.get('data') or {}).get('access_token') or ''
    if not token:
        raise RuntimeError('oauth/token 返回空 access_token')
    return token


def cem_request(path, body, access_token, device_id='', timeout=30.0):
    payload = json.dumps(body, separators=(',', ':')).encode('utf-8')
    req = urllib.request.Request(CEM_BASE + path, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', 'Bearer ' + access_token)
    req.add_header('gzs-client-id', CEM_CLIENT_ID)
    req.add_header('gzs-timestamp', str(int(time.time() * 1000)))
    req.add_header('sc-terminal-sn', device_id or '')
    req.add_header('sc-network-type', '2')
    req.add_header('sc-unit-type', 'MacBookPro')
    req.add_header('User-Agent', 'cdpsdk-macos-2.18.21(2.18.21.159)')
    with _NO_PROXY_OPENER.open(req, timeout=timeout) as res:
        return json.loads(res.read().decode('utf-8', 'replace'))


def wait_vm_ready(access_token, vm_id, trace_id, device_id='', timeout=30.0,
                  attempts=20, interval=3.0):
    """轮询 VM 就绪状态；可能带回刷新后的 scAuthCode"""
    if not trace_id:
        raise RuntimeError('traceId 为空，无法等待就绪')
    vm_encrypted = _cem_rsa_encrypt(vm_id)
    last_error = 'not ready'
    for attempt in range(max(1, int(attempts))):
        result = cem_request(
            '/sc/open-portal/openapi/terminal/v1/getVmReadyStatus',
            {'vmId': vm_encrypted, 'traceId': trace_id},
            access_token, device_id=device_id, timeout=timeout)
        if result.get('code') == '00000' or result.get('returnCode') == '00000':
            data = result.get('data') or {}
            if str(data.get('readyStatus')) == '1':
                return {'readyStatus': 1, 'scAuthCode': data.get('scAuthCode') or ''}
            last_error = 'readyStatus=%r' % (data.get('readyStatus'),)
        else:
            last_error = 'code=%s msg=%s' % (
                result.get('code') or result.get('returnCode'),
                result.get('msg') or result.get('returnMsg'))
        if attempt + 1 < int(attempts):
            time.sleep(max(0.0, float(interval)))
    raise RuntimeError('VM 就绪超时: %s' % last_error)


def get_connect_info(sc_auth_code, vm_id, device_id='', timeout=30.0):
    """CEM getConnectInfo —— 本身就会触发 SCG VM 开机"""
    access_token = exchange_cem_access_token(sc_auth_code, timeout=timeout)
    result = cem_request(
        '/sc/open-portal/openapi/terminal/v1/getConnectInfo',
        {'vmId': _cem_rsa_encrypt(vm_id)}, access_token, device_id=device_id, timeout=timeout)
    if result.get('code') != '00000' and result.get('returnCode') != '00000':
        raise RuntimeError('getConnectInfo code=%s msg=%s' % (
            result.get('code') or result.get('returnCode'),
            result.get('msg') or result.get('returnMsg')))
    data = result.get('data') or {}
    scg_ip = data.get('scgIp') or data.get('scgIP') or ''
    if not scg_ip:
        raise RuntimeError('getConnectInfo 返回空 scgIp')
    info = {
        'scgIp': scg_ip,
        'scgPort': str(data.get('scgTcpPort') or data.get('scgPort') or '10800'),
        'scAuthCode': data.get('scAuthCode') or sc_auth_code,
        'traceId': data.get('traceId') or '',
        'readyStatus': data.get('readyStatus'),
    }
    if str(info['readyStatus']) != '1' and info['traceId']:
        ready = wait_vm_ready(access_token, vm_id, str(info['traceId']),
                              device_id=device_id, timeout=timeout)
        if ready.get('scAuthCode'):
            info['scAuthCode'] = ready['scAuthCode']
        info['readyStatus'] = ready.get('readyStatus', 1)
    return info


# ---------------------------------------------------------------------------
# SPICE 长连接保活：委托 1936-zero/cmcc-cloud-alive（MIT）
# ---------------------------------------------------------------------------
_REF_PATHS = [
    os.environ.get('CMCC_ALIVE_PATH', ''),
    '/opt/cmcc-alive',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cmcc-alive'),
]


def find_ref_pkg():
    """找到参考包则返回 scg_route 模块；找不到返回 None。"""
    for p in _REF_PATHS:
        if p and os.path.isfile(os.path.join(p, 'cmcc_cloud_alive', 'scg_route.py')):
            if p not in sys.path:
                sys.path.insert(0, p)
            try:
                from cmcc_cloud_alive import scg_route  # noqa
                return scg_route
            except Exception:
                continue
    return None


def run_keepalive_session(firm_data, device_id='', duration=120):
    """一次保活会话。
    firm_data: firm_auth 返回的 data（含 scAuthCode / vmId / scgIp / scgTcpPort）
    返回 {'mode': 'spice'|'connect', ...}
    """
    sc_auth_code = firm_data.get('scAuthCode') or ''
    vm_id = str(firm_data.get('vmId') or '')
    if not sc_auth_code or not vm_id:
        raise RuntimeError('firm_auth 数据里缺 scAuthCode/vmId（可能不是 SCG 线路）')

    # 先走一次 getConnectInfo（触发连接事件 / 开机 / 刷新 scAuthCode）
    ci = get_connect_info(sc_auth_code, vm_id, device_id=device_id)

    route = find_ref_pkg()
    if route is not None:
        res = route.run_scg_keepalive(
            ci['scgIp'], ci['scgPort'], ci['scAuthCode'], vm_id,
            duration=duration, mode='spice')
        out = {'mode': 'spice', 'scg': '%s:%s' % (ci['scgIp'], ci['scgPort'])}
        # SCGKeepaliveResult 是 dataclass：returncode / stdout 之类
        for attr in ('returncode', 'stdout'):
            try:
                out[attr] = getattr(res, attr)
            except Exception:
                pass
        if hasattr(res, '__dict__'):
            out.update({k: v for k, v in vars(res).items()
                        if isinstance(v, (int, float, str, bool))})
        return out
    # 降级：参考包不存在，只触发连接事件
    return {'mode': 'connect', 'scg': '%s:%s' % (ci['scgIp'], ci['scgPort']),
            'readyStatus': ci.get('readyStatus')}


def is_scg(firm_data):
    """firm_auth 数据是否为 SCG（深信服）线路"""
    return bool(firm_data and firm_data.get('scAuthCode'))
