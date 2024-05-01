@echo off
@title Launcher

python --version 2>NUL
if errorlevel 1 (
	echo Python not installed or not added to the PATH environmental variable. Install Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
	pause
	exit
)

python -c "import sys; exit(0 if sys.version_info >= (3, 12) else 1)"
if errorlevel 1 (
	echo Python version too old. Minimum required version is 3.12. Upgrade Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
	pause
	exit
)

set "oldVirtualEnvironmentFolder=oldEnv"
set "virtualEnvironmentFolder=env"

if exist %oldVirtualEnvironmentFolder%\ (
  echo Doing cleanup
  rmdir /S /Q %oldVirtualEnvironmentFolder%
) else (
  echo No cleanup to do
)

call %virtualEnvironmentFolder%\scripts\activate.bat

if '%errorlevel%' NEQ '0' (
	echo No virtual environment found. Creating...
	python -m venv %virtualEnvironmentFolder%
	call %virtualEnvironmentFolder%\scripts\activate.bat
@REM    pip install requests
@REM    pip install flask
@REM    pip install frida
@REM    pip install pycryptodome
@REM    pip install pure-python-adb
@REM 	pip install uv
@REM	uv pip install -r pyproject.toml
) else (
	echo Found virtual environment. Running...
)

echo Checking for updates...
python launch_game.py