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

REM Loop #71: this used to be
REM   set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
REM a path that exists on exactly one machine in this repository's history. On
REM a GitHub windows-latest runner it expanded to a path that is not there, and
REM the only line the gate could show was the batch's own echo:
REM   BUILD FAILED / The system cannot find the path specified.
REM build_poly1305.bat already resolved this correctly with `where`. The other
REM eight had not heard of it. Same rule now, in all nine -- and a missing
REM compiler says so by name, because "no compiler" and "compiler failed" are
REM different failures and the second used to hide the first.
if defined GCC goto :cc_ready
where gcc >nul 2>&1
if not errorlevel 1 (
  set GCC=gcc
  goto :cc_ready
)
where clang >nul 2>&1
if not errorlevel 1 (
  set GCC=clang
  goto :cc_ready
)
echo no C compiler on PATH: neither gcc nor clang was found
exit /b 1
:cc_ready
echo using %GCC%
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
