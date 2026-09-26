# Deploys mt-agent on the RDP box (Windows Server 2012 R2+, Windows 8.1+).
# Run as Administrator.
#Requires -RunAsAdministrator

# Why not a real Windows Service: pointing binPath at powershell.exe -File does
# not work - SCM requires a service that implements ServiceMain, so start fails
# with error 1053 / "CouldNotStartService". A scheduled task at system startup,
# running as SYSTEM, gives us the equivalent and actually starts on 2012 R2 /
# PowerShell 4.

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest    = 'C:\mt-agent'
$boot    = 'MTAgentBoot'       # session 0, SYSTEM: heartbeat+metrics, survives logoff
$logon   = 'MTAgentLogon'      # your RDP session: live screen + remote control
$exe     = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

# --- install into a SYSTEM-readable location (a user profile folder is not) ---
if ((Resolve-Path $here).Path -ne $dest) {
    if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
    Copy-Item (Join-Path $here 'agent.ps1')     $dest -Force
    Copy-Item (Join-Path $here 'config.json')   $dest -Force
    Copy-Item (Join-Path $here 'uninstall.ps1') $dest -Force -EA SilentlyContinue
    Write-Host "installed to $dest"
} else { Write-Host "already running from $dest" }

# remove the broken service if a previous install left one
if (Get-Service -Name 'MTAgent' -EA SilentlyContinue) {
    Stop-Service -Name 'MTAgent' -Force -EA SilentlyContinue
    sc.exe delete MTAgent | Out-Null
    Write-Host "removed obsolete MTAgent service"
}

$agent = Join-Path $dest 'agent.ps1'
$cmd   = "$exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agent`""

# --- session 0 copy: heartbeat + metrics + commands. Runs as SYSTEM at boot. ---
schtasks /Delete /TN $boot /F 2>$null | Out-Null
schtasks /Create /TN $boot /TR $cmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "boot task '$boot' created (SYSTEM, session 0)" }
else { Write-Host "WARNING: boot task creation failed (exit $LASTEXITCODE)" }

# --- interactive copy: screen capture + remote input. Your RDP session. ---
schtasks /Delete /TN $logon /F 2>$null | Out-Null
schtasks /Create /TN $logon /TR $cmd /SC ONLOGON /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "logon task '$logon' created" }
else { Write-Host "WARNING: logon task creation failed (exit $LASTEXITCODE)" }

Write-Host ""
Write-Host "Starting both now (no reboot, no re-login needed)..."
schtasks /Run /TN $boot  | Out-Null
schtasks /Run /TN $logon | Out-Null
Start-Sleep -Seconds 4
schtasks /Query /TN $boot  /FO LIST | Findstr 'TaskName Status "Run As User"'
schtasks /Query /TN $logon /FO LIST | Findstr 'TaskName Status "Run As User"'
Write-Host ""
Write-Host "Next step: check your dashboard - heartbeat should appear within ~30s."
Write-Host "If the screen panel stays black, the interactive copy is not in your"
Write-Host "RDP session. Re-login to RDP, or run in a normal (non-admin) window:"
Write-Host "  powershell -ExecutionPolicy Bypass -File $agent"
Write-Host ""
Write-Host "Uninstall:  $dest\uninstall.ps1"
