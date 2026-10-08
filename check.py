#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
部署自检脚本 —— 换服务器后先跑它，一次性把环境问题全查出来
==========================================================
用法:  python3 check.py           （或 python3 check.py --port 8765）

检查项：
  1. Python 版本 >= 3.9
  2. 程序文件完整性
  3. data 目录可写
  4. 二维码生成器自检（纯本地算法）
  5. 官方服务器连通性：直连 / 系统代理 两条路分别测试
  6. SSL 证书链是否被本机信任（老系统 CA 过期是常见坑）
  7. 系统时间偏差（签名带时间戳，偏差过大会被服务端拒绝）
  8. 目标端口是否可绑定
"""
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

GREEN = '\033[32m' if sys.platform != 'win32' else ''
RED = '\033[31m' if sys.platform != 'win32' else ''
YEL = '\033[33m' if sys.platform != 'win32' else ''
END = '\033[0m' if sys.platform != 'win32' else ''

RESULTS = []


def report(name, ok, detail='', warn=False):
    RESULTS.append((name, ok, warn))
    tag = ('%sPASS%s' % (GREEN, END)) if ok else (
        ('%sWARN%s' % (YEL, END)) if warn else ('%sFAIL%s' % (RED, END)))
    print('  [%s] %s%s' % (tag, name, ('  —— ' + detail) if detail else ''))


def opener(use_proxy):
    if use_proxy:
        return urllib.request.build_opener()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe(use_proxy, timeout=15):
    """探测官方服务器；返回 (ok, detail)"""
    url = 'https://soho.komect.com/terminal/login/encryptKey/v1'
    req = urllib.request.Request(url, data=b'', method='POST')
    req.add_header('Content-Type', 'application/json')
    t0 = time.time()
    try:
        with opener(use_proxy).open(req, timeout=timeout) as r:
            body = r.read(200)
            date_hdr = r.headers.get('Date')
        return True, 'HTTP %s，耗时 %.1fs，返回 %d 字节%s' % (
            r.status, time.time() - t0, len(body),
            ('（服务端时间 %s）' % date_hdr) if date_hdr else ''), r.headers
    except urllib.error.HTTPError as e:
        # 有响应说明链路通（哪怕业务码不对）
        return True, 'HTTP %s（链路可达）' % e.code, getattr(e, 'headers', None)
    except Exception as e:
        return False, '%s: %s' % (type(e).__name__, e), None


def main():
    print('=' * 64)
    print(' CMCC 云电脑保活 · 部署自检')
    print(' 目录: %s' % BASE_DIR)
    print('=' * 64)

    # 1. Python 版本（qrcodegen.py 用了 list[int] 注解，需要 3.9+）
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 9)
    report('Python 版本', ok, '%d.%d.%d' % (v.major, v.minor, v.micro))
    if not ok:
        print('\n%sPython 版本过低，请升级到 3.9+%s' % (RED, END))
        return 1

    # 2. 文件完整性
    need = ['cmcc_api.py', 'server.py', 'panel.html', 'qr.py', 'qrcodegen.py']
    missing = [f for f in need if not os.path.exists(os.path.join(BASE_DIR, f))]
    report('程序文件完整性', not missing,
           '缺失: %s' % ','.join(missing) if missing else '%d 个文件齐全' % len(need))

    # 3. data 目录可写
    data_dir = os.path.join(BASE_DIR, 'data')
    try:
        os.makedirs(data_dir, exist_ok=True)
        p = os.path.join(data_dir, '.write_test')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('ok')
        os.remove(p)
        report('data 目录可写', True, data_dir)
    except Exception as e:
        report('data 目录可写', False, str(e))

    # 4. 二维码生成器
    try:
        import qr
        m, ver = qr.encode_matrix('https://soho.komect.com/test?token=abc')
        png, _ = qr.make_qr_png('https://soho.komect.com/test?token=abc')
        report('二维码生成器', len(png) > 100 and len(m) > 20,
               'v%d 矩阵 %dx%d，PNG %d 字节' % (ver, len(m), len(m), len(png)))
    except Exception as e:
        report('二维码生成器', False, '%s: %s' % (type(e).__name__, e))

    # 5/6. 连通性：先直连，再代理
    print('\n  正在探测官方服务器 soho.komect.com ...')
    direct_ok, direct_msg, hdrs = probe(False)
    report('官方服务器 · 直连', direct_ok, direct_msg)

    proxy_env = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy') \
        or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    if proxy_env:
        p_ok, p_msg, p_hdrs = probe(True)
        report('官方服务器 · 系统代理', p_ok, p_msg)
        if not direct_ok and not p_ok:
            print('    %s两条路都不通，请检查网络/代理/DNS%s' % (RED, END))
        hdrs = hdrs or p_hdrs
    else:
        print('    （未检测到代理环境变量 HTTP_PROXY/HTTPS_PROXY，跳过代理探测）')

    if not direct_ok:
        # 细分：DNS / SSL / 连接
        try:
            socket.getaddrinfo('soho.komect.com', 443, proto=socket.IPPROTO_TCP)
            report('DNS 解析', True, 'soho.komect.com 可解析')
        except Exception as e:
            report('DNS 解析', False, str(e))
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(('soho.komect.com', 443), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname='soho.komect.com') as ss:
                    report('SSL 证书验证', True, 'TLS %s，证书可信' % ss.version())
        except ssl.SSLCertVerificationError as e:
            report('SSL 证书验证', False,
                   '证书链不被信任（系统 CA 过旧？）: %s\n'
                   '      → 修复: apt install -y ca-certificates && update-ca-certificates\n'
                   '      → 应急: 用 CMCC_INSECURE=1 启动（跳过验证，不建议长期用）' % e)
        except Exception as e:
            report('SSL/TLS 握手', False, '%s: %s' % (type(e).__name__, e))

    # 7. 系统时间偏差（用 HTTP Date 头对比）
    if hdrs and hdrs.get('Date'):
        try:
            from email.utils import parsedate_to_datetime
            import datetime
            svr = parsedate_to_datetime(hdrs['Date'])
            if svr.tzinfo is None:
                svr = svr.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            diff = abs((svr - now).total_seconds())
            report('系统时间偏差', diff < 60, '与服务端相差 %.0f 秒%s'
                   % (diff, '' if diff < 60 else '（签名用时间戳，偏差过大会被拒绝！请 ntpdate 校时）'),
                   warn=(60 <= diff < 3600))
        except Exception as e:
            report('系统时间偏差', True, '无法比对(%s)' % e, warn=True)
    else:
        report('系统时间偏差', True, '跳过（未拿到服务端时间）', warn=True)

    # 8. 端口
    port = 8765
    for i, a in enumerate(sys.argv):
        if a == '--port' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    s = socket.socket()
    # 不设 SO_REUSEADDR：Windows 下它会允许重复绑定已监听端口，导致误判为可用
    try:
        s.bind(('0.0.0.0', port))
        report('端口 %d 可绑定' % port, True, '')
    except Exception as e:
        report('端口 %d 可绑定' % port, False,
               '%s（换端口: python3 server.py --port 8766）' % e)
    finally:
        s.close()

    # 汇总
    print('\n' + '=' * 64)
    fails = [r for r in RESULTS if not r[1] and not r[2]]
    warns = [r for r in RESULTS if r[2]]
    if not fails:
        print('  %s全部通过 ✔%s   可以直接启动：' % (GREEN, END))
        print('     python3 -u server.py --port %d' % port)
    else:
        print('  %s有 %d 项未通过，按上面的提示修复后再启动%s' % (RED, len(fails), END))
    if warns:
        print('  %s%d 项警告（不影响启动，建议留意）%s' % (YEL, len(warns), END))
    print('=' * 64)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
