#!/usr/bin/env bash
# ============================================================
# 移动云电脑保活 · 一键部署脚本（Ubuntu / Debian / CentOS）
# 用法:  bash deploy.sh          # 默认端口 8765
#        CMCC_PORT=80 bash deploy.sh
# 说明:  拷贝本目录到服务器后执行；先自检环境，再装 systemd 服务并启动
# ============================================================
set -e

APP_NAME="cmcc-keepalive"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${CMCC_PORT:-8765}"

echo "==========================================="
echo " CMCC 云电脑保活服务 部署"
echo " 目录 : $DIR"
echo " 端口 : $PORT"
echo "==========================================="

# ---------- 1. Python ----------
PY="$(command -v python3 || echo /usr/bin/python3)"
if [ ! -x "$PY" ]; then
  echo "[!] 未找到 python3，请先安装：apt install -y python3"
  exit 1
fi
VER="$($PY -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
MAJ="${VER%%.*}"; MIN="${VER##*.}"
echo "[1/5] Python: $($PY --version 2>&1)"
if [ "$MAJ" -lt 3 ] || { [ "$MAJ" -eq 3 ] && [ "$MIN" -lt 7 ]; }; then
  echo "[!] Python 版本过低（需要 3.7+），当前 $VER"
  exit 1
fi

mkdir -p "$DIR/data"

# ---------- 2. 环境自检 ----------
echo "[2/5] 环境自检（联网/证书/时间/端口）"
if ! "$PY" "$DIR/check.py" --port "$PORT"; then
  echo
  echo "[!] 自检未通过。若只是端口被占用，换端口重试："
  echo "    CMCC_PORT=8766 bash deploy.sh"
  echo "    若网络不通，先修复网络再部署（保活服务必须能访问 soho.komect.com）"
  read -r -p "    仍要继续部署吗？[y/N] " yn
  case "$yn" in
    [Yy]*) echo "    继续部署（请稍后自行修复上述问题）" ;;
    *) exit 1 ;;
  esac
fi

# ---------- 3. systemd ----------
echo "[3/5] 写入 systemd 服务 /etc/systemd/system/${APP_NAME}.service"
sudo tee /etc/systemd/system/${APP_NAME}.service > /dev/null <<EOF
[Unit]
Description=CMCC Cloud PC Keep-Alive Panel (${APP_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DIR}
Environment=CMCC_PORT=${PORT}
# 面板访问密码（取消注释并改成自己的）
#Environment=CMCC_PANEL_PASS=change-me
# 网络必须走代理时才开：
#Environment=CMCC_USE_PROXY=1
# 老系统 SSL 证书过旧导致 certificate verify failed 时的应急开关：
#Environment=CMCC_INSECURE=1
ExecStart=${PY} -u ${DIR}/server.py --host 0.0.0.0 --port ${PORT}
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# ---------- 4. 启动 ----------
echo "[4/5] 启动服务"
sudo systemctl daemon-reload
sudo systemctl enable ${APP_NAME}
sudo systemctl restart ${APP_NAME}
sleep 3

# ---------- 5. 状态 ----------
echo "[5/5] 运行状态"
sudo systemctl --no-pager -l status ${APP_NAME} | head -14 || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "==========================================="
echo " 部署完成"
echo " 面板地址: http://${IP:-<服务器IP>}:${PORT}/"
echo " 自检接口: http://${IP:-<服务器IP>}:${PORT}/api/check"
echo
echo " 常用命令:"
echo "   查看日志 : sudo journalctl -u ${APP_NAME} -f"
echo "   重启服务 : sudo systemctl restart ${APP_NAME}"
echo "   停止服务 : sudo systemctl stop ${APP_NAME}"
echo "   重新自检 : python3 ${DIR}/check.py --port ${PORT}"
echo
echo " 若面板打不开，多半是端口未放行："
echo "   云平台安全组放行 ${PORT}"
echo "   Ubuntu : sudo ufw allow ${PORT}/tcp"
echo "   CentOS : sudo firewall-cmd --add-port=${PORT}/tcp --permanent && sudo firewall-cmd --reload"
echo
echo " 不建议裸奔公网：设置 CMCC_PANEL_PASS 或前置 nginx + HTTPS"
echo "==========================================="
