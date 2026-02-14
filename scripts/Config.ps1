$VMName = "vm1"
$LocalDest = "./minidumps"
$User = "RobotAdmin"
$Pass = "Passw0rd1231"
$DriverName = "example-driver"

$SecPass = ConvertTo-SecureString $Pass -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($User, $SecPass)

if (!(Test-Path $LocalDest)) { New-Item -ItemType Directory -Path $LocalDest -ErrorAction SilentlyContinue }

Write-Host ">>> Config Loaded for VM: $VMName" -ForegroundColor Gray