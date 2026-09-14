@echo off
setlocal

cd /d "%~dp0"

rem Portable release optimization: keep the artifact runnable on generic x86_64
rem Linux hosts; do not use target-cpu=native for distributable binaries.
set "CARGO_PROFILE_RELEASE_OPT_LEVEL=3"
set "CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1"
set "CARGO_PROFILE_RELEASE_LTO=thin"
set "CARGO_PROFILE_RELEASE_STRIP=true"

set "TARGET=x86_64-unknown-linux-musl"
set "OUTPUT=%~dp0target\%TARGET%\release\newppp"

where zig >nul 2>nul
if errorlevel 1 (
    echo zig was not found.
    echo Install Zig from: https://ziglang.org/download/
    exit /b 1
)

cargo zigbuild --help >nul 2>nul
if errorlevel 1 (
    echo cargo-zigbuild was not found.
    echo Install it with: cargo install cargo-zigbuild
    exit /b 1
)

echo Building Newppp for generic Linux with Zig (static musl binary)...
rem Zig 0.16 emits a deprecated -Wl,-O1 compatibility notice; it is not a Rust warning.
set "RUSTFLAGS=-A linker_messages %RUSTFLAGS%"
cargo zigbuild --release --target %TARGET% --manifest-path "%~dp0Cargo.toml"

if errorlevel 1 (
    echo.
    echo Linux build failed.
    exit /b 1
)

echo.
echo Linux build succeeded:
echo %OUTPUT%
echo.
echo This is a statically linked x86_64 Linux binary.
exit /b 0
