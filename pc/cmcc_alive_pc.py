# -*- coding: utf-8 -*-
"""
移动云电脑 · 单文件保活器（放云电脑里跑的"套娃"版）
====================================================
用法（exe 版直接双击；py 版 python cmcc_alive_pc.py）：
  1. 首次运行：输入手机号 -> 收到短信验证码 -> 输入 -> 登录
  2. 自动拉取名下云电脑并开始保活循环：
       每 30 分钟：firm_auth(新码) -> CEM getConnectInfo -> SPICE 桌面会话(120秒)
     （自动关机计时器只认桌面连接活动，心跳 API 没用——所以必须建真会话）
  3. Ctrl+C 退出。登录态保存在同目录 cmcc_alive_pc.json，下次免登录。

依赖：无（py 版需 cryptography；exe 版已内置）。
协议来源：1936-zero/cmcc-cloud-alive (MIT) + 本人对官方客户端的逆向。
"""
import getpass
import json
import os
import sys
import time
import traceback

# exe 跑在 exe 所在目录；py 版跑在脚本所在目录
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from cmcc_api import CMCCApi, make_device_profile, CODE_OK, CODE_UNTOKEN, CODE_H5_LOGINED
import scg

STATE_FILE = os.path.join(BASE_DIR, 'cmcc_alive_pc.json')
INTERVAL_MIN = 30          # 保活间隔（分钟）
SPICE_DURATION = 120       # 每次 SPICE 会话时长（秒）


def log(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def load_state():
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(st, f, ensure_ascii=False, indent=1)
    except Exception as e:
        log('!! 保存状态失败: %s' % e)


def do_login():
    """短信登录，返回 api + 登录数据"""
    print('=' * 52)
    print(' 移动云电脑保活器 · 首次登录')
    print('=' * 52)
    phone = input('手机号: ').strip()
    if not phone:
        raise SystemExit('手机号不能为空')
    api = CMCCApi(device=make_device_profile(model='X64', release='10.0.19045'), timeout=20)
    r = api.send_sms(phone)
    if r.get('code') != CODE_OK:
        raise SystemExit('验证码发送失败: [%s] %s' % (r.get('code'), r.get('msg')))
    print('  验证码已发送到手机。')
    code = getpass.getpass('短信验证码: ').strip()
    r = api.sms_login(phone, code)
    if r.get('code') != CODE_OK or not r.get('data'):
        raise SystemExit('登录失败: [%s] %s' % (r.get('code'), r.get('msg')))
    d = r['data']
    api.collect_info()
    return api, d


def main():
    st = load_state()
    api = None
    if st.get('sohoToken') and st.get('userId'):
        api = CMCCApi(device=st.get('device') or make_device_profile(),
                      soho_token=st['sohoToken'], user_id=st['userId'], timeout=20)
        r = api.check_token()
        if r.get('code') != CODE_OK:
            log('已保存的登录态失效（[%s] %s），需要重新登录' % (r.get('code'), r.get('msg')))
            api = None
        else:
            log('使用已保存的登录态（%s）' % st.get('phone', ''))
    if api is None:
        api, d = do_login()
        st = {
            'phone': d.get('phone') or d.get('userPhone') or '',
            'userId': str(d.get('userId') or ''),
            'sohoToken': d.get('sohoToken') or '',
            'device': api.device,
        }
        save_state(st)
        log('登录成功：%s' % st['phone'])

    # 拉设备列表
    items = api.list_cloud_pcs()
    if isinstance(items, dict):
        items = items.get('data', [])
    if not items:
        raise SystemExit('该账号名下没有云电脑')
    log('名下云电脑 %d 台：' % len(items))
    for it in items:
        log('  [%s] %s（%s）' % (it.get('userServiceId'), it.get('vmName'), it.get('vmStatusShow')))
    usids = [int(it['userServiceId']) for it in items]

    print()
    log('开始保活循环：每 %d 分钟一轮 SCG·SPICE 会话（每会话 %d 秒）。Ctrl+C 退出。'
        % (INTERVAL_MIN, SPICE_DURATION))
    print('-' * 52)

    rounds = 0
    while True:
        rounds += 1
        # 登录态校验
        try:
            r = api.check_token()
            if r.get('code') in CODE_UNTOKEN or r.get('code') == CODE_H5_LOGINED:
                log('!! 登录态已失效（改密码/别处登录/被顶）。删除 %s 后重新运行本程序。'
                    % os.path.basename(STATE_FILE))
                input('按回车退出...')
                return
        except Exception as e:
            log('checkToken 网络异常: %s' % e)

        # 每台设备一轮真保活
        for sid in usids:
            try:
                fa = api.firm_auth(sid)
                if fa.get('code') != CODE_OK or not fa.get('data'):
                    log('[%s] firm_auth 失败 [%s] %s' % (sid, fa.get('code'), fa.get('msg')))
                    continue
                data = fa['data']
                if not scg.is_scg(data):
                    log('[%s] 非 SCG 线路（ZTE），本版本暂只支持 SCG' % sid)
                    continue
                out = scg.run_keepalive_session(
                    data, device_id=(st.get('device') or {}).get('deviceId', ''),
                    duration=SPICE_DURATION)
                log('[%s] 保活完成 —— SCG·%s %s' % (sid, out.get('mode'), out.get('scg', '')))
            except Exception as e:
                log('[%s] 保活失败: %s' % (sid, str(e)[:150]))

        if rounds == 1:
            log('第 1 轮完成。下一轮 %d 分钟后。' % INTERVAL_MIN)
        # 睡眠到下一轮（可被 Ctrl+C 打断）
        try:
            for _ in range(INTERVAL_MIN * 60):
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        if rounds > 1:
            log('第 %d 轮开始。' % (rounds + 1))


def _pause():
    try:
        input('按回车退出...')
    except Exception:
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        log('已退出。')
    except SystemExit as e:
        print(str(e))
        _pause()
    except Exception:
        traceback.print_exc()
        _pause()
