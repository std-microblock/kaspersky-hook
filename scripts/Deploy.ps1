$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Connecting to VM: $VMName" -ForegroundColor Green

Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true

Copy-VMFile -VMName $VMName -SourcePath ".\build\windows\x64\releasedbg\$DriverName.sys" -DestinationPath "C:\" -FileSource Host -Force
Copy-VMFile -VMName $VMName -SourcePath ".\src\klhk.sys" -DestinationPath "C:\" -FileSource Host -Force

Write-Host ">>> Configuring Registry and Starting Service..." -ForegroundColor Yellow

Invoke-Command -VMName $VMName -Credential $Cred -ScriptBlock {
    param($Svc)
    
    sc.exe create klhk binPath= "C:\klhk.sys" type= kernel start= demand error= normal DisplayName= "Kaspersky Lab service driver" | Out-Null
    sc.exe create $Svc binPath= "C:\$Svc.sys" type= kernel start= demand error= normal DisplayName= "$Svc Service" | Out-Null

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\klhk\Parameters"
    
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    New-ItemProperty -Path $regPath -Name "UseHvm" -Value 1 -PropertyType DWord -Force | Out-Null

    Write-Host "Starting klhk..."
    sc.exe start klhk
    
    Write-Host "Starting $Svc..."
    sc.exe start $Svc
} -ArgumentList $DriverName