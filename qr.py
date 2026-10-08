# -*- coding: utf-8 -*-
"""
二维码生成（服务端本地生成，不经过任何第三方）
================================================
只为「扫码登录」这一个场景服务：把登录 URL 编成二维码 PNG。
只依赖 zlib + struct（Python 标准库）+ 同目录的 qrcodegen.py。

编码核心用的是 Nayuki QR-Code-generator（MIT License，纯标准库单文件，
久经实战验证的参考实现）。旧版手写编码器在格式信息/掩码上有 bug，
生成的图 OpenCV/手机都解不出来，已整体替换——教训：
「自己写的编码器配自己写的解码器做 round-trip」发现不了共同的假设错误。

对外接口（server.py / check.py 依赖，签名保持不变）：
  make_qr_png(text, scale=8, border=4) -> (png_bytes, version)
  encode_matrix(text)                  -> (matrix, version)
  to_png(matrix, scale, border)        -> png_bytes

自检：python qr.py   （生成样例二维码，若装有 OpenCV 则顺带真解码验证）
"""

import struct
import zlib

from qrcodegen import QrCode  # 本地单文件库，MIT


def encode_matrix(text, ecc=QrCode.Ecc.MEDIUM):
    """生成 QR 矩阵。返回 (matrix, version)；matrix[r][c] ∈ {0,1}，1=黑"""
    qr = QrCode.encode_text(text or '', ecc)
    size = qr.get_size()
    m = [[1 if qr.get_module(c, r) else 0 for c in range(size)] for r in range(size)]
    return m, qr.get_version()


# ---------------------------------------------------------------------------
# PNG 输出（8bit 灰度）
# ---------------------------------------------------------------------------
def to_png(matrix, scale=8, border=4):
    size = len(matrix)
    dim = (size + border * 2) * scale
    rows = []
    # 边框白底
    blank = bytearray([255] * dim)
    for _ in range(border * scale):
        rows.append(bytes(blank))
    for r in range(size):
        line = bytearray([255] * dim)
        for c in range(size):
            v = 0 if matrix[r][c] else 255
            x0 = (border + c) * scale
            for _ in range(scale):
                line[x0:x0 + scale] = bytes([v] * scale)
        for _ in range(scale):
            rows.append(bytes(line))
    for _ in range(border * scale):
        rows.append(bytes(blank))

    raw = b''.join(b'\x00' + r for r in rows)

    def chunk(tag, data):
        return (struct.pack('>I', len(data)) + tag + data +
                struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', dim, dim, 8, 0, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(raw, 9))
    png += chunk(b'IEND', b'')
    return png


def make_qr_png(text, scale=8, border=4):
    m, ver = encode_matrix(text)
    return to_png(m, scale, border), ver


if __name__ == '__main__':
    url = ('http://hsop.komect.com:18080/appdl/redirect.html'
           '?token=aea88b19130746e9a79c22348ce4a47a&expireTime=10&lgScanType=third')
    png, ver = make_qr_png(url, scale=8, border=4)
    open('qr_selftest.png', 'wb').write(png)
    m, _ = encode_matrix(url)
    size = len(m)
    # 结构自检：三个定位图案必须齐全（左上/右上/左下 7x7）
    def finder_ok(r0, c0):
        for dr in range(7):
            for dc in range(7):
                expect = 1 if (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4)) else 0
                if m[r0 + dr][c0 + dc] != expect:
                    return False
        return True
    assert finder_ok(0, 0) and finder_ok(0, size - 7) and finder_ok(size - 7, 0), '定位图案异常'
    print('QR 版本 v%d · %dx%d 模块 · PNG %d 字节 -> qr_selftest.png' % (ver, size, size, len(png)))
    try:
        import cv2
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(cv2.imread('qr_selftest.png'))
        assert data == url, '真解码不一致: %r' % data
        print('OpenCV 真解码验证通过:', data[:60], '...')
    except ImportError:
        print('（未安装 OpenCV，跳过真解码验证；可用手机扫 qr_selftest.png 确认）')
