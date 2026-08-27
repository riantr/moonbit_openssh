@echo off
REM Build poly1305 verification harness using OpenSSH's original poly1305.c
cd /d "%~dp0"

REM Try gcc first, then clang
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
  echo Using gcc
  gcc -I . -o poly1305_kat.exe poly1305_harness.c 2>&1
  goto :check
)

where clang >nul 2>&1
if %ERRORLEVEL% == 0 (
  echo Using clang
  clang -I . -o poly1305_kat.exe poly1305_harness.c 2>&1
  goto :check
)

echo No C compiler found
exit /b 1

:check
if exist poly1305_kat.exe (
  echo Build OK, running...
  poly1305_kat.exe
) else (
  echo Build FAILED
  exit /b 1
)
