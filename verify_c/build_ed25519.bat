@echo off
REM Ed25519 KAT harness build script
REM Compiles ed25519_harness.c with OpenSSH's original ed25519.c (public domain)
REM and sha2.c (BSD) providing SHA-512. Verifies MoonBit Ed25519 against the
REM same C reference on RFC 8032 KAT vectors.
REM
REM Loop #55: the `%%` below used to be `%`. Inside a REM line cmd still expands
REM a lone `%`, so every run printed "'%' is not recognized" before the build --
REM harmless, but it trained everyone to ignore noise in this script's output,
REM which is a bad property for the one script a gate shells out to.
REM
REM Loop #55 also deletes the previous exe before building. A stale binary that
REM still passes is the Loop #47 failure exactly: the gate reports PASS for a
REM tree it did not compile.

set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
cd /d "%~dp0"

if exist ed25519_kat.exe del /q ed25519_kat.exe

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
