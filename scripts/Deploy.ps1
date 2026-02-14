$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Connecting to VM: $VMName" -ForegroundColor Green

Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true
Copy-VMFile -VMName $VMName -SourcePath ".\build\windows\x64\releasedbg\$DriverName.sys" -DestinationPath "C:\" -FileSource Host -Force

Write-Host ">>> Starting Service..." -ForegroundColor Yellow
Invoke-Command -VMName $VMName -Credential $Cred -ScriptBlock {
    param($Svc)
    sc.exe create $Svc binPath= "C:\$Svc.sys" type= kernel start= demand error= normal DisplayName= "$Svc Service" | Out-Null
    sc.exe stop $Svc | Out-Null
    sc.exe start $Svc
} -ArgumentList $DriverName
