# Removes the mt-monitor agent (service + logon task).
#Requires -RunAsAdministrator

$svc  = 'MTAgent'
$boot = 'MTAgentBoot'
$task = 'MTAgentLogon'

# boot task replaced the broken service; uninstall both tasks
schtasks /Delete /TN $boot /F 2>$null | Out-Null
Write-Host "boot task '$boot' removed (if it existed)"

# schtasks.exe instead of the *ScheduledTask cmdlets - works on PS 4 / 2012 R2
schtasks /Delete /TN $task /F 2>$null | Out-Null
Write-Host "logon task '$task' removed (if it existed)"

if (Get-Service -Name $svc -EA SilentlyContinue) {
    Stop-Service -Name $svc -Force -EA SilentlyContinue
    sc.exe delete $svc | Out-Null
    Write-Host "service '$svc' removed"
} else { Write-Host "service '$svc' not found" }

Write-Host "Done. Heartbeats will stop within ~5 seconds."
