# 统一构建环境：显式 PATH/INCLUDE/LIB，绕开本机失效的 vcvars64（见 AGENTS.md 踩坑 28）。
# 用法：powershell -NoProfile -File scripts/cargo-env.ps1 check --lib
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs)

$ErrorActionPreference = 'Stop'
$msvc = Get-ChildItem 'C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC' -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
$sdk = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Lib' -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvc -or -not $sdk) { throw '未找到 MSVC 或 Windows SDK' }

$env:Path = "$env:USERPROFILE\.cargo\bin;$($msvc.FullName)\bin\Hostx64\x64;$($sdk.Parent.FullName)\bin\$($sdk.Name)\x64;$env:Path"
$env:INCLUDE = @(
    "$($msvc.FullName)\include"
    "C:\Program Files (x86)\Windows Kits\10\Include\$($sdk.Name)\ucrt"
    "C:\Program Files (x86)\Windows Kits\10\Include\$($sdk.Name)\shared"
    "C:\Program Files (x86)\Windows Kits\10\Include\$($sdk.Name)\um"
    "C:\Program Files (x86)\Windows Kits\10\Include\$($sdk.Name)\winrt"
) -join ';'
$env:LIB = @(
    "$($msvc.FullName)\lib\x64"
    "C:\Program Files (x86)\Windows Kits\10\Lib\$($sdk.Name)\ucrt\x64"
    "C:\Program Files (x86)\Windows Kits\10\Lib\$($sdk.Name)\um\x64"
) -join ';'
$env:CARGO_HTTP_CHECK_REVOKE = 'false'

Push-Location (Join-Path $PSScriptRoot '..\src-tauri')
try { & cargo @CargoArgs; exit $LASTEXITCODE } finally { Pop-Location }
