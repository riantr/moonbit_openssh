@echo off
REM HMAC-SHA512 KAT harness build script
REM Compiles hmac_sha512_harness.c with OpenBSD sha2.c (BSD-licensed)
REM Verifies MoonBit HMAC-SHA512 against the same RFC 4231 KATs

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building hmac_sha512_kat.exe ...
%GCC% -o hmac_sha512_kat.exe hmac_sha512_harness.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
echo Running RFC 4231 KAT verification ...
.\hmac_sha512_kat.exe
exit /b %ERRORLEVEL%
