@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  start "" "http://127.0.0.1:8000"
  py -m http.server 8000 --bind 127.0.0.1
  goto :end
)

where python >nul 2>nul
if %errorlevel%==0 (
  start "" "http://127.0.0.1:8000"
  python -m http.server 8000 --bind 127.0.0.1
  goto :end
)

echo Python was not found on this computer.
echo Install Python, then run this file again.
pause

:end
endlocal
