@echo off
REM Ed25519 KAT harness build script
REM Compiles ed25519_harness.c with OpenSSH's original ed25519.c (public domain)
REM and sha2.c (BSD) providing SHA-512. Verifies MoonBit Ed25519 against the
%% same C reference on RFC 8032 KAT vectors.

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

echo Building ed25519_kat.exe ...
%GCC% -O2 -o ed25519_kat.exe ed25519_harness.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
echo Running RFC 8032 KAT verification ...
.\ed25519_kat.exe
exit /b %ERRORLEVEL%
