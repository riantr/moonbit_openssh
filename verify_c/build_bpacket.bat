@echo off
REM Loop #10 binary packet harness: OpenSSH real chacha.c + poly1305.c +
REM aead_chachapoly_ref.c vs python-generated packet vectors

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building bpacket_kat.exe ...
%GCC% -O2 -Wall -o bpacket_kat.exe bpacket_harness.c aead_chachapoly_ref.c chacha.c poly1305.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
.\bpacket_kat.exe
exit /b %ERRORLEVEL%
