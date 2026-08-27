@echo off
REM Loop #9 KEX harness: OpenSSH smult_curve25519_ref.c + sshbuf (real
REM put_bignum2_bytes) + sha2.c vs python-generated vectors.

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building kex_kat.exe ...
%GCC% -O2 -Wall -o kex_kat.exe kex_harness.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
.\kex_kat.exe
exit /b %ERRORLEVEL%
