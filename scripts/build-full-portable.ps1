# F-7 完整便携版组装脚本（本地手动执行）。
#
# 固定版本 WebView2 运行时无法在无网/无显示环境自动下载验证，需先手工获取：
#   1. 打开 https://developer.microsoft.com/microsoft-edge/webview2/
#   2. 在「Fixed Version deployment」下载与目标匹配的 Fixed Distribution（.cab）。
#   3. 用 expand 命令解包：
#        expand <下载>.cab -F:* <解包目录>
#      解包后目录内应有 msedgewebview2.exe（含若干子目录）。
#
# 用法（在仓库根目录）：
#   pwsh -File scripts/build-full-portable.ps1 -WebView2Dir "<解包目录>"
#
# 产物：dist-release/ClaudeSwitcher-full-portable.zip
# 运行时 run() 会检测到 webview2\msedgewebview2.exe 并设置
# WEBVIEW2_BROWSER_EXECUTABLE_FOLDER，无需系统安装 WebView2。

param(
  [Parameter(Mandatory = $true)]
  [string]$WebView2Dir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $root 'src-tauri\target\release'
$staging = Join-Path $root 'full-portable-staging'
$outDir = Join-Path $root 'dist-release'

if (-not (Test-Path -LiteralPath (Join-Path $WebView2Dir 'msedgewebview2.exe'))) {
  throw "WebView2Dir 下找不到 msedgewebview2.exe：$WebView2Dir"
}
foreach ($bin in @('claude-switcher.exe', 'cs.exe')) {
  if (-not (Test-Path -LiteralPath (Join-Path $releaseDir $bin))) {
    throw "找不到 $bin，请先执行 release 构建（target/release）。"
  }
}

if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
New-Item -ItemType Directory -Force $staging | Out-Null

Copy-Item (Join-Path $releaseDir 'claude-switcher.exe') (Join-Path $staging 'ClaudeSwitcher.exe')
Copy-Item (Join-Path $releaseDir 'cs.exe') (Join-Path $staging 'cs.exe')
New-Item -ItemType File (Join-Path $staging 'portable.flag') | Out-Null

# 固定运行时整体复制到 webview2\ 子目录（paths::fixed_webview2_dir 检测此目录）。
Copy-Item -LiteralPath $WebView2Dir -Destination (Join-Path $staging 'webview2') -Recurse

New-Item -ItemType Directory -Force $outDir | Out-Null
$zip = Join-Path $outDir 'ClaudeSwitcher-full-portable.zip'
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip

$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
Write-Output "Built: $zip"
Write-Output "SHA256: $hash"
