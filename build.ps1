$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "[*] Building file_blinder_dll.dll..." -ForegroundColor Cyan
Push-Location "$ScriptDir\file_blinder_dll"
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "DLL build failed" }
} finally {
    Pop-Location
}

Write-Host "[*] Building file_blinder_injector.exe..." -ForegroundColor Cyan
Push-Location "$ScriptDir\file_blinder_injector"
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "Injector build failed" }
} finally {
    Pop-Location
}

Write-Host "[*] Copying binaries to $ScriptDir..." -ForegroundColor Cyan
Copy-Item -Force "$ScriptDir\file_blinder_dll\target\release\file_blinder_dll.dll" "$ScriptDir\file_blinder_dll.dll"
Copy-Item -Force "$ScriptDir\file_blinder_injector\target\release\file_blinder_injector.exe" "$ScriptDir\file_blinder_injector.exe"

Write-Host "[+] Build complete!" -ForegroundColor Green
Get-Item "$ScriptDir\file_blinder_dll.dll", "$ScriptDir\file_blinder_injector.exe" | Format-Table Name, Length, LastWriteTime
