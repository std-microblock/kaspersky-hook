$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Fetching latest Minidump..." -ForegroundColor Cyan

$RemoteScript = {
    $file = Get-ChildItem "C:\Windows\Minidump\*.dmp" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($file) {
        return @{ Name = $file.Name; Data = [System.IO.File]::ReadAllBytes($file.FullName) }
    }
}

$Result = Invoke-Command -VMName $VMName -Credential $Cred -ScriptBlock $RemoteScript

if ($Result -and $Result.Data) {
    $FilePath = Join-Path $LocalDest $Result.Name
    [System.IO.File]::WriteAllBytes($FilePath, $Result.Data)
    Write-Host "Done! Saved to: $FilePath" -ForegroundColor Green
} else {
    Write-Warning "No dump files found."
}