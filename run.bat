@echo off
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting Bug Bounty Scanner...
python bb_scanner.py
pause
