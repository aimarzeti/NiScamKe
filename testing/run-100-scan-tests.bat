@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-100-scan-tests.ps1" %*
