Write-Host ">>> Rebuilding..." -ForegroundColor Cyan
xmake f -m releasedbg -c
xmake -r

if ($LASTEXITCODE -eq 0) {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    . "$PSScriptRoot\Deploy.ps1"
}