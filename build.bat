@echo off
cd /d "%~dp0"

echo [*] Building file_blinder_dll.dll...
cd file_blinder_dll
cargo build --release || goto :fail
cd ..

echo [*] Building file_blinder_injector.exe...
cd file_blinder_injector
cargo build --release || goto :fail
cd ..

echo [*] Copying binaries...
copy /y "file_blinder_dll\target\release\file_blinder_dll.dll" "file_blinder_dll.dll" >nul
copy /y "file_blinder_injector\target\release\file_blinder_injector.exe" "file_blinder_injector.exe" >nul

echo [+] Build complete!
dir "file_blinder_dll.dll" "file_blinder_injector.exe"
exit /b 0

:fail
echo [-] Build FAILED
exit /b 1
