@echo off
setlocal
python -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
if not errorlevel 1 (
  python "%~dp0avb_mode_tool.py" %*
  exit /b
)
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
if not errorlevel 1 (
  py -3 "%~dp0avb_mode_tool.py" %*
  exit /b
)
echo Python 3.8 or later is required. Install Python and enable PATH.
exit /b 2
