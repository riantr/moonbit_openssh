@echo off
REM Loop #11 hostkey harness: real sshbuf (get_cstring/get_string/
REM get_bignum2_bytes_direct) + real ed25519.c + transcribed dispatch
REM vs python-generated KAT vectors (_hostkey_kat.h)

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
