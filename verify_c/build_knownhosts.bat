@echo off
REM Loop #13 known_hosts C harness:独立 SHA-1 + HMAC-SHA1 + base64 + NFA + parse + check
REM 引用 _knownhosts_kat.h (由 gen_knownhosts_test.py 从 _knownhosts_ref_out.txt 生成)
REM 通过 tcc / gcc 直接编译运行验证 byte-exact

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building knownhosts_kat.exe ...
%GCC% -O2 -Wall -o knownhosts_kat.exe knownhosts_harness.c -lm
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
.\knownhosts_kat.exe
exit /b %ERRORLEVEL%
