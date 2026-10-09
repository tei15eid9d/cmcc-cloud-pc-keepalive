# -*- coding: utf-8 -*-
"""
移动云电脑保活面板 · PC 单文件版（带 Web 面板）
================================================
双击运行：自动启动面板服务并打开浏览器 http://127.0.0.1:8765/
 - 账号数据存在 exe 旁边 data/accounts.json
 - 面板功能与服务器版一致：扫码/短信登录、SCG 真保活、真开机、日志
 - 关闭本窗口 = 停止保活
"""
import os
import sys
import threading
import webbrowser

PORT = int(os.environ.get('CMCC_PORT', '8765'))


def main():
    sys.argv = [sys.argv[0], '--host', '127.0.0.1', '--port', str(PORT)]
    # 3 秒后自动打开浏览器
    threading.Timer(3.0, lambda: webbrowser.open('http://127.0.0.1:%d/' % PORT)).start()
    print('=' * 56)
    print(' 移动云电脑保活面板（PC 版）')
    print(' 浏览器没自动打开就手动访问: http://127.0.0.1:%d/' % PORT)
    print(' 关闭本窗口即停止保活。账号数据在 exe 旁 data/ 目录。')
    print('=' * 56, flush=True)
    import server
    server.main()


if __name__ == '__main__':
    main()
