@echo off
REM Loop #12 KEX flow harness: real smult_curve25519_ref + real sshbuf +
REM real chachapoly + real SHA-256 + Python-generated vectors.

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building kexflow_kat.exe ...
%GCC% -O2 -Wall -o kexflow_kat.exe kexflow_harness.c -lm
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
.\kexflow_kat.exe
exit /b %ERRORLEVEL%
