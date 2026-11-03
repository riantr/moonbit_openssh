@echo off
REM Blowfish / bcrypt_pbkdf KAT harness build script
REM Compiles blowfish_harness.c with OpenSSH's own openbsd-compat/blowfish.c
REM and openbsd-compat/bcrypt_pbkdf.c (copied here as blowfish_ref.c and
REM bcrypt_pbkdf_ref.c by host/blowfish_ref.py) plus OpenBSD's sha2.c.
REM
REM The vectors this produces are what src/blowfish and src/bcrypt_pbkdf
REM are checked against.  The algorithm is OpenSSH's, not ours.
REM
REM The same compiler-resolution rule as the other nine build scripts:
REM "no compiler" and "compiler failed" are different failures, and the
REM second one used to hide the first one.
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

echo Building blowfish_kat.exe ...
%GCC% -o blowfish_kat.exe blowfish_harness.c
if %ERRORLEVEL% NEQ 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
echo.
echo The reference vectors are printed by the harness; host/blowfish_kat.py
echo reads them and checks them against the committed MoonBit tests.
.\blowfish_kat.exe
exit /b %ERRORLEVEL%
