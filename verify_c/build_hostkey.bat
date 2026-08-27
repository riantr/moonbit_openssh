@echo off
REM Loop #11 hostkey harness: real sshbuf (get_cstring/get_string/
REM get_bignum2_bytes_direct) + real ed25519.c + transcribed dispatch
REM vs python-generated KAT vectors (_hostkey_kat.h)

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building hostkey_kat.exe ...
%GCC% -O2 -Wall -o hostkey_kat.exe hostkey_harness.c 2> _hostkey_build_err.log
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED - see _hostkey_build_err.log
  exit /b 1
)
echo BUILD OK
echo.
.\hostkey_kat.exe
exit /b %ERRORLEVEL%
