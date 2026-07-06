@echo off
:: HenkerDPI V2 — Admin olarak başlat
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
py gui.py
