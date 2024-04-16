@echo off
@title Launcher

python --version 2>NUL
if errorlevel 1 (
	echo Python not installed or not added to the PATH environmental variable. Install Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
	pause
	exit
)

python -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
	echo Python version too old. Minimum required version is 3.11. Upgrade Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
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
   pip install requests
   pip install flask
   pip install frida
   pip install pycryptodome
   pip install pure-python-adb
	::pip install uv
	::uv pip install -r pyproject.toml
) else (
	echo Found virtual environment. Running...
)

echo Checking for updates...
python launch_game.py