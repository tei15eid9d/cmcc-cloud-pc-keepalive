# -*- coding: utf-8 -*-
"""
纯标准库 QR Code 编码器（byte mode / 纠错等级 L）
================================================
只为「扫码登录」这一个场景服务：把登录 URL 编成二维码 PNG。
不依赖 qrcode / PIL，只用 zlib + struct（Python 标准库）。

实现范围：
  * 版本 1-10 自动选择（L 级最大 274 字节，登录 URL 绰绰有余）
  * byte mode (0100)、纠错等级 L(01)
  * 8 种掩码 + 惩罚评分择优（掩码在 format info 中声明，任何掩码都能被正确解码）
  * 输出 8bit 灰度 PNG

自检：python qr.py    （编码 -> 反向解码 round-trip 验证）
"""

import struct
import zlib

# ---------------------------------------------------------------------------
# GF(256) 运算，本原多项式 0x11d
# ---------------------------------------------------------------------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a == 0:
            continue
        for j, b in enumerate(q):
            r[i + j] ^= gf_mul(a, b)
    return r


def _rs_generator(n):
    """生成多项式 (x-α^0)(x-α^1)...(x-α^(n-1))，返回长度 n+1，首项 1"""
    g = [1]
    for i in range(n):
        g = _poly_mul(g, [1, _EXP[i]])
    return g


def _rs_encode(data, ecc_len):
    """多项式除法取余，返回 ecc_len 个纠错码字"""
    gen = _rs_generator(ecc_len)
    res = list(data) + [0] * ecc_len
    for i in range(len(data)):
        coef = res[i]
        if coef == 0:
            continue
        for j in range(1, len(gen)):
            res[i + j] ^= gf_mul(gen[j], coef)
    return res[len(data):]


# ---------------------------------------------------------------------------
# 版本参数表（纠错等级 L）
#   (数据码字总数, 每块纠错码字数, [各块的数据码字数...])
# ---------------------------------------------------------------------------
SPEC = {
    1: (19, 7, [19]),
    2: (34, 10, [34]),
    3: (55, 15, [55]),
    4: (80, 20, [80]),
    5: (108, 26, [108]),
    6: (136, 18, [68, 68]),
    7: (156, 20, [78, 78]),
    8: (194, 24, [97, 97]),
    9: (232, 30, [116, 116]),
    10: (274, 18, [68, 69, 68, 69]),
}

ALIGN_POS = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

EC_L_BITS = 0x01  # 纠错等级 L -> 01


def _bch_format(data5):
    """5 bit format -> 15 bit (BCH(15,5)) ^ 0x5412"""
    rem = data5
    for _ in range(10):
        rem = ((rem << 1) ^ (0x537 if (rem >> 9) & 1 else 0)) & 0x3FF
    return (((data5 << 10) | rem) ^ 0x5412) & 0x7FFF


def _bch_version(ver):
    """6 bit version -> 18 bit (BCH(18,6))"""
    rem = ver
    for _ in range(12):
        rem = ((rem << 1) ^ (0x1F25 if (rem >> 11) & 1 else 0)) & 0xFFF
    return (ver << 12) | rem


# ---------------------------------------------------------------------------
# 编码主流程
# ---------------------------------------------------------------------------
def _pick_version(byte_len):
    for ver in range(1, 11):
        cc_bits = 8 if ver <= 9 else 16
        need_bits = 4 + cc_bits + 8 * byte_len
        if SPEC[ver][0] * 8 >= need_bits:
            return ver
    raise ValueError('数据过长，超过版本 10 的容量')


def _data_codewords(data_bytes, ver):
    """byte mode 位流 -> 码字列表（含终止符与补齐）"""
    cc_bits = 8 if ver <= 9 else 16
    bits = '0100'
    bits += format(len(data_bytes), '0%db' % cc_bits)
    for b in data_bytes:
        bits += format(b, '08b')
    cap = SPEC[ver][0] * 8
    # 终止符 0000
    bits += '0' * min(4, cap - len(bits))
    # 补齐到字节边界
    while len(bits) % 8:
        bits += '0'
    # 填充字节 EC 11 交替
    pad = [0xEC, 0x11]
    i = 0
    while len(bits) < cap:
        bits += format(pad[i % 2], '08b')
        i += 1
    return [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]


def _interleave(data_cw, ver):
    """分块 -> RS -> 交织"""
    total, ecc_len, blocks_spec = SPEC[ver]
    blocks, pos = [], 0
    for n in blocks_spec:
        blocks.append(data_cw[pos:pos + n])
        pos += n
    ecc_blocks = [_rs_encode(b, ecc_len) for b in blocks]
    out = []
    max_len = max(len(b) for b in blocks)
    for i in range(max_len):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ecc_len):
        for e in ecc_blocks:
            out.append(e[i])
    return out


def _build_matrix(ver, codewords):
    size = 4 * ver + 17
    m = [[None] * size for _ in range(size)]

    def set_rc(r, c, v):
        if 0 <= r < size and 0 <= c < size:
            m[r][c] = v

    # 定位图案 + 分隔符
    finder = [
        [1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1],
    ]
    for br, bc in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = br + dr, bc + dc
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                if 0 <= dr <= 6 and 0 <= dc <= 6:
                    m[rr][cc] = finder[dr][dc]
                else:
                    m[rr][cc] = 0

    # 定时图案
    for i in range(size):
        if m[6][i] is None:
            m[6][i] = 1 if i % 2 == 0 else 0
        if m[i][6] is None:
            m[i][6] = 1 if i % 2 == 0 else 0

    # 校正图案
    apos = ALIGN_POS[ver]
    for r in apos:
        for c in apos:
            if (r, c) in ((apos[0], apos[0]), (apos[0], apos[-1]), (apos[-1], apos[0])):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    v = 1 if (abs(dr) == 2 or abs(dc) == 2 or (dr == 0 and dc == 0)) else 0
                    set_rc(r + dr, c + dc, v)

    # 固定黑模块 + 预留格式/版本区
    m[4 * ver + 9][8] = 1
    for i in range(9):
        if m[8][i] is None:
            m[8][i] = 0
        if m[i][8] is None:
            m[i][8] = 0
    for i in range(8):
        if m[8][size - 1 - i] is None:
            m[8][size - 1 - i] = 0
        if m[size - 1 - i][8] is None:
            m[size - 1 - i][8] = 0
    m[size - 8][8] = 1      # 格式区固定黑模块
    m[8][size - 8] = 1      # 格式区固定黑模块
    if ver >= 7:
        for i in range(6):
            for j in range(3):
                set_rc(i, size - 11 + j, 0)
                set_rc(size - 11 + j, i, 0)

    # 版本信息
    if ver >= 7:
        vb = _bch_version(ver)
        for i in range(18):
            bit = (vb >> i) & 1
            m[i // 3][size - 11 + i % 3] = bit
            m[size - 11 + i % 3][i // 3] = bit

    # 数据位流
    bits = ''.join(format(c, '08b') for c in codewords)
    bit_idx = 0
    col = size - 1
    up = True
    while col > 0:
        if col == 6:
            col -= 1
        for i in range(size):
            row = (size - 1 - i) if up else i
            for c in (col, col - 1):
                if m[row][c] is None:
                    m[row][c] = int(bits[bit_idx]) if bit_idx < len(bits) else 0
                    bit_idx += 1
        col -= 2
        up = not up
    return m


def _mask_fn(k, r, c):
    if k == 0:
        return (r + c) % 2 == 0
    if k == 1:
        return r % 2 == 0
    if k == 2:
        return c % 3 == 0
    if k == 3:
        return (r + c) % 3 == 0
    if k == 4:
        return (r // 2 + c // 3) % 2 == 0
    if k == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if k == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _penalty(m):
    """简化惩罚评分：统计连续同色 run（>5 记罚），用于挑选掩码"""
    size = len(m)
    score = 0
    for line in (m, [[m[r][c] for r in range(size)] for c in range(size)]):
        for row in line:
            run, prev = 1, row[0]
            for v in row[1:]:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += run - 2
                    run, prev = 1, v
            if run >= 5:
                score += run - 2
    # 同色 2x2 块惩罚
    for r in range(size - 1):
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    return score


def encode_matrix(data: str):
    """字符串 -> (二维 0/1 矩阵, 版本号)"""
    raw = data.encode('utf-8')
    ver = _pick_version(len(raw))
    cw = _data_codewords(raw, ver)
    stream = _interleave(cw, ver)
    m = _build_matrix(ver, stream)

    size = len(m)
    # 记录功能模块位置（掩码只作用于数据区）
    reserved = [[True] * size for _ in range(size)]   # True = 功能模块，不参与掩码
    # 重新判定：功能模块 = 定位/分隔/定时/校正/格式/版本区
    fpos = set()
    for br, bc in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = br + dr, bc + dc
                if 0 <= rr < size and 0 <= cc < size:
                    fpos.add((rr, cc))
    for i in range(size):
        fpos.add((6, i))
        fpos.add((i, 6))
    apos = ALIGN_POS[ver]
    for r in apos:
        for c in apos:
            if (r, c) in ((apos[0], apos[0]), (apos[0], apos[-1]), (apos[-1], apos[0])):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    fpos.add((r + dr, c + dc))
    for i in range(9):
        fpos.add((8, i))
        fpos.add((i, 8))
    for i in range(8):
        fpos.add((8, size - 1 - i))
        fpos.add((size - 1 - i, 8))
    if ver >= 7:
        for i in range(6):
            for j in range(3):
                fpos.add((i, size - 11 + j))
                fpos.add((size - 11 + j, i))
    fpos.add((4 * ver + 9, 8))

    best, best_score, best_mask = None, None, 0
    for k in range(8):
        cand = [row[:] for row in m]
        for r in range(size):
            for c in range(size):
                if (r, c) in fpos:
                    continue
                if _mask_fn(k, r, c):
                    cand[r][c] ^= 1
        s = _penalty(cand)
        if best_score is None or s < best_score:
            best, best_score, best_mask = cand, s, k

    # 写入格式信息
    fmt = _bch_format((EC_L_BITS << 3) | best_mask)
    for i in range(15):
        bit = (fmt >> i) & 1
        if i < 6:
            best[8][i] = bit
        elif i == 6:
            best[8][7] = bit
        elif i == 7:
            best[8][8] = bit
        elif i == 8:
            best[7][8] = bit
        else:
            best[14 - i][8] = bit
        if i < 8:
            best[size - 1 - i][8] = bit
        else:
            best[8][size - 15 + i] = bit
    return best, ver


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


# ---------------------------------------------------------------------------
# 自检：反向解码 round-trip
# ---------------------------------------------------------------------------
def _decode_matrix(m, ver):
    """把矩阵里的数据区按 zigzag 读回码字（用于自检）"""
    size = len(m)
    apos = ALIGN_POS[ver]
    fpos = set()
    for br, bc in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = br + dr, bc + dc
                if 0 <= rr < size and 0 <= cc < size:
                    fpos.add((rr, cc))
    for i in range(size):
        fpos.add((6, i))
        fpos.add((i, 6))
    for r in apos:
        for c in apos:
            if (r, c) in ((apos[0], apos[0]), (apos[0], apos[-1]), (apos[-1], apos[0])):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    fpos.add((r + dr, c + dc))
    for i in range(9):
        fpos.add((8, i))
        fpos.add((i, 8))
    for i in range(8):
        fpos.add((8, size - 1 - i))
        fpos.add((size - 1 - i, 8))
    if ver >= 7:
        for i in range(6):
            for j in range(3):
                fpos.add((i, size - 11 + j))
                fpos.add((size - 11 + j, i))
    fpos.add((4 * ver + 9, 8))

    # 读掩码
    fmt_bits = []
    for i in range(15):
        if i < 6:
            fmt_bits.append(m[8][i])
        elif i == 6:
            fmt_bits.append(m[8][7])
        elif i == 7:
            fmt_bits.append(m[8][8])
        elif i == 8:
            fmt_bits.append(m[7][8])
        else:
            fmt_bits.append(m[14 - i][8])
    fmt = 0
    for i, b in enumerate(fmt_bits):   # fmt_bits[i] 对应第 i 位（LSB=0）
        fmt |= b << i
    fmt ^= 0x5412
    mask_k = (fmt >> 10) & 0x07
    ec_bits = (fmt >> 13) & 0x03

    bits = []
    col = size - 1
    up = True
    while col > 0:
        if col == 6:
            col -= 1
        for i in range(size):
            row = (size - 1 - i) if up else i
            for c in (col, col - 1):
                if (row, c) in fpos:
                    continue
                v = m[row][c]
                if _mask_fn(mask_k, row, c):
                    v ^= 1
                bits.append(v)
        col -= 2
        up = not up

    cw = []
    for i in range(0, len(bits) - 7, 8):
        b = 0
        for x in bits[i:i + 8]:
            b = (b << 1) | x
        cw.append(b)
    return cw, mask_k, ec_bits


def _selftest():
    samples = [
        'https://soho.komect.com/h5/login?token=abc123',
        'A',
        'https://base.hjq.komect.com/appconfig/index/webauth/index?type=ydn&lgToken=9f8e7d6c5b4a3210&t=1791450000',
        'x' * 120,
    ]
    ok = True
    for s in samples:
        m, ver = encode_matrix(s)
        cw, mask_k, ec_bits = _decode_matrix(m, ver)
        # 去交织还原数据
        total, ecc_len, blocks_spec = SPEC[ver]
        blocks, pos = [], 0
        for n in blocks_spec:
            blocks.append(list(range(pos, pos + n)))
            pos += n
        # 交织顺序还原
        data_idx = []
        max_len = max(len(b) for b in blocks)
        for i in range(max_len):
            for b in blocks:
                if i < len(b):
                    data_idx.append(b[i])
        # 反交织：cw[k] 对应原始数据中的第 interleave_order[k] 个码字
        interleave_order = []
        for i in range(max_len):
            for b in blocks:
                if i < len(b):
                    interleave_order.append(b[i])
        recovered = [0] * total
        for k, orig_idx in enumerate(interleave_order):
            recovered[orig_idx] = cw[k]
        raw_bits = ''.join(format(c, '08b') for c in recovered[:total])
        mode = raw_bits[:4]
        cc_bits = 8 if ver <= 9 else 16
        length = int(raw_bits[4:4 + cc_bits], 2)
        payload = bytes(int(raw_bits[4 + cc_bits + 8 * i: 12 + cc_bits + 8 * i], 2)
                        for i in range(length))
        good = (mode == '0100' and payload.decode('utf-8') == s and ec_bits == 0x01)
        ok = ok and good
        print('%-5s ver=%-2d mask=%d ec=%s len=%-3d %s' % (
            'PASS' if good else 'FAIL', ver, mask_k, bin(ec_bits), length, s[:48]))
    print('\nSELFTEST:', 'OK' if ok else 'FAILED')
    return 0 if ok else 1


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
