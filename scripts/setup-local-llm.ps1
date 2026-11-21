#Requires -Version 5.1
param(
    [switch]$Offline,
    [string]$FromCache
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
if ($env:OS -ne 'Windows_NT' -or $architecture -ne 'AMD64') {
    throw 'This installer targets Windows x64.'
}

$project = Split-Path -Parent $PSScriptRoot
$python = Join-Path $project '.venv/Scripts/python.exe'
$prefix = @()
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $python = $launcher.Source
        $prefix = @('-3')
    } else {
        $interpreter = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $interpreter) { throw 'Install Python 3.12+ and make it available as py or python.' }
        $python = $interpreter.Source
    }
}
& $python @prefix -B -c 'import sys; sys.exit(sys.version_info < (3, 12))'
if ($LASTEXITCODE -ne 0) { throw 'Local Qwen setup requires Python 3.12 or newer.' }

$options = @()
if ($Offline) { $options += '--offline' }
if ($FromCache) {
    $cache = (Resolve-Path -LiteralPath $FromCache).Path
    if (-not (Test-Path -LiteralPath $cache -PathType Container)) { throw '-FromCache must point to a directory.' }
    $options += @('--from-cache', $cache)
}
Push-Location -LiteralPath $project
try {
    & $python @prefix -B -m backend.local_llm_assets @options
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
