@echo off
REM Loop #8 AEAD harness: OpenSSH original cipher-chachapoly.c + chacha.c
REM + poly1305.c vs python-generated vectors (aead_python_ref.py)

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building aead_kat.exe ...
%GCC% -O2 -Wall -o aead_kat.exe aead_harness.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
.\aead_kat.exe
exit /b %ERRORLEVEL%
