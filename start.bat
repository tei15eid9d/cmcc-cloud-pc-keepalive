@echo off
chcp 65001 >nul
title 移动云电脑保活面板
cd /d "%~dp0"
echo ==========================================
echo   移动云电脑保活面板 - 本地启动
echo ==========================================
echo.
where python >nul 2>nul
if %errorlevel%==0 (
  set PY=python
) else (
  set PY=py
)
echo 使用 Python: %PY%
echo 面板地址: http://127.0.0.1:8765/
echo 按 Ctrl+C 停止服务
echo.
%PY% -u server.py --port 8765
pause
