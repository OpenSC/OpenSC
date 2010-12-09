@echo off

rem This script installs OpenSC
rem Parameters:
rem     user - Install for this user only.

setlocal

set MODE=%1

set KEY=HKEY_LOCAL_MACHINE
if "%MODE%" == "user" set KEY=HKEY_CURRENT_USER

cd %0\..\..

if not exist bin\opensc-tool.exe goto error

for /f %%f in (".") do set OPENSC_HOME=%%~ff

set OPENSC_HOME_ESCAPED=%OPENSC_HOME:\=\\%
set REG_FILE=%TEMP%\opensc-install.reg

echo Windows Registry Editor Version 5.00 > %REG_FILE%
echo [%KEY%\SOFTWARE\OpenSC Project\OpenSC] >> %REG_FILE%
echo "ConfigFile"="%OPENSC_HOME_ESCAPED%\\etc\\opensc.conf" >> %REG_FILE%
echo [%KEY%\SOFTWARE\PKCS11-Spy] >> %REG_FILE%
echo "Module"="%OPENSC_HOME_ESCAPED%\\bin\\opensc-pkcs11.dll" >> %REG_FILE%

regedit /s %REG_FILE%
del /q %REG_FILE%

"%OPENSC_HOME%\bin\opensc-tool" -S "app:default:profile_dir:%OPENSC_HOME%\share\opensc"

echo You may also want to add "%OPENSC_HOME%\bin" to your PATH, for use by other applications.

goto end

:error
echo Invalid installation
goto end

:end

endlocal
