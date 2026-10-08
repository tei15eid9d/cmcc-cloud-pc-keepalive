FROM python:3.11-slim

WORKDIR /app
COPY cmcc_api.py server.py panel.html qr.py check.py ./
RUN mkdir -p /app/data

ENV CMCC_PORT=8765
EXPOSE 8765

# 启动前先跑一次自检（网络/证书/时间/端口），失败不启动，便于定位环境问题
CMD ["sh", "-c", "python check.py --port ${CMCC_PORT} && python -u server.py --host 0.0.0.0 --port ${CMCC_PORT}"]
