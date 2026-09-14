@echo off
setlocal

cd /d "%~dp0"

rem Portable release optimization: keep the artifact runnable on generic
rem Windows x86_64 hosts; do not use target-cpu=native for distributable builds.
set "CARGO_PROFILE_RELEASE_OPT_LEVEL=3"
set "CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1"
set "CARGO_PROFILE_RELEASE_LTO=thin"
set "CARGO_PROFILE_RELEASE_STRIP=true"

echo Building Newppp (release)...
cargo build --release --manifest-path "%~dp0Cargo.toml"

if errorlevel 1 (
    echo.
    echo Release build failed.
    exit /b 1
)

echo.
echo Release build succeeded:
echo %~dp0target\release\newppp.exe
exit /b 0
