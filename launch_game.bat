@ECHO OFF
@TITLE ODPy

python --version 2>NUL
if ERRORLEVEL 1 (
	ECHO Python not installed or not added to the PATH environmental variable. Install Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
	PAUSE
	EXIT
)

python -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"
IF ERRORLEVEL 1 (
	ECHO Python version too old. Minimum required version is 3.11. Upgrade Python at https://www.python.org/downloads and make sure to select 'Add Python to environmental variables' when installing.
	PAUSE
	EXIT
)

SET "venv=env"

CALL %venv%\scripts\activate.bat

IF '%errorlevel%' NEQ '0' (
	ECHO No virtual environment found. Creating...
	python -m venv %venv%
	CALL %venv%\scripts\activate.bat
	pip install uv
	uv pip install frida pure-python-adb regex requests flask pycryptodome
) ELSE (
	ECHO Found virtual environment. Running...
)

ECHO Checking for updates...
python launch_game.py

PAUSE