#Requires -Version 4.0
<#
  mtmon agent - Windows RDP / MetaTrader
  Sends signed heartbeats + JPEG screenshots, polls a command queue.

  Self-detecting role:
    - session 0 (service, LocalSystem): heartbeat + metrics + commands only.
      Screen capture and SendInput cannot reach the RDP desktop from session 0,
      so they are skipped (black frames + dead mouse are worse than no data).
    - interactive/RDP session: full mode - heartbeat + screen + input + commands.

  Deploy: copy mt-agent\ to C:\mt-agent\, edit config.json, run install-service.ps1
  Console test: .\agent.ps1
#>
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg  = Get-Content "$here\config.json" -Raw | ConvertFrom-Json

# single-instance per role (service and interactive copy may coexist)
$SessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$Role      = if ($SessionId -ne 0) { 'session' } else { 'service' }
# per-session mutex: multi-user RDP boxes get one interactive copy per logon
$lock      = New-Object System.Threading.Mutex($false, "Global\MTAgent-$Role-$SessionId")
if (-not $lock.WaitOne(0, $false)) { "Another mtmon agent ($Role) is running."; exit 1 }

# ---------- TLS: Windows Server 2012 R2 / PS 4 defaults to TLS 1.0 ----------
# Our HTTPS server only negotiates TLS 1.2+. Without this, the agent aborts with
# "Could not create SSL/TLS secure channel".
try   { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
catch { [Net.ServicePointManager]::SecurityProtocol = 3072 }  # numeric TLS 1.2 (.NET 4.0)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- epoch time (.NET 4.5 safe; ToUnixTimeSeconds needs 4.6+) ----------
$Epoch = [DateTime]::SpecifyKind((New-Object DateTime(1970, 1, 1)), [DateTimeKind]::Utc)
function Now-Epoch { return [int64]([DateTime]::UtcNow - $Epoch).TotalSeconds }

# ---------- remote input: SendInput ----------
$VK = @{
  Enter=13; Escape=27; Tab=9; Backspace=8; Delete=46; Insert=45;
  Home=36; End=35; PageUp=33; PageDown=34;
  Left=37; Up=38; Right=39; Down=40;
  Shift=16; Control=17; Alt=18; Space=32;
  F1=112; F2=113; F3=114; F4=115; F5=116; F6=117; F7=118; F8=119; F9=120; F10=121; F11=122; F12=123;
}
Add-Type @"
using System; using System.Runtime.InteropServices;
public class MTInput {
  [StructLayout(LayoutKind.Sequential)]
  public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Sequential)]
  public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Sequential)]
  public struct HARDWAREINPUT { public uint uMsg; public ushort wParamL; public ushort wParamH; }
  [StructLayout(LayoutKind.Explicit)]
  public struct INPUTUNION {
    [FieldOffset(0)] public MOUSEINPUT mi;
    [FieldOffset(0)] public KEYBDINPUT ki;
    [FieldOffset(0)] public HARDWAREINPUT hi;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT { public uint type; public INPUTUNION u; }
  [DllImport("user32.dll", SetLastError=true)]
  public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
  [DllImport("user32.dll")]
  public static extern int GetSystemMetrics(int nIndex);
}
"@ -EA SilentlyContinue

function Send-InputEvents($events) {
  if (-not $events -or $events.Count -eq 0) { return 0 }
  $SM_CXSCREEN = 0; $SM_CYSCREEN = 1
  $sw = [MTInput]::GetSystemMetrics($SM_CXSCREEN)
  $sh = [MTInput]::GetSystemMetrics($SM_CYSCREEN)
  $buf = New-Object 'MTInput[]' $events.Count
  $i = 0
  foreach ($e in $events) {
    $inp = New-Object MTInput
    switch ($e.t) {
      'move' {
        $inp.type = 0   # INPUT_MOUSE
        $inp.u.mi.dx = [int]([double]$e.x / [double]$sw * 65535.0)
        $inp.u.mi.dy = [int]([double]$e.y / [double]$sh * 65535.0)
        $inp.u.mi.dwFlags = 0x8001   # MOUSEEVENTF_ABSOLUTE | MOVE
      }
      'down' {
        $inp.type = 0
        $inp.u.mi.dwFlags = if ($e.b -eq 'right') { 0x0008 } elseif ($e.b -eq 'middle') { 0x0020 } else { 0x0002 }
      }
      'up' {
        $inp.type = 0
        $inp.u.mi.dwFlags = if ($e.b -eq 'right') { 0x0010 } elseif ($e.b -eq 'middle') { 0x0040 } else { 0x0004 }
      }
      'scroll' {
        $inp.type = 0
        $inp.u.mi.mouseData = if ($e.dy -and $e.dy -lt 0) { [uint32](-([int]$e.dy)) } else { 120 }
        $inp.u.mi.dwFlags = 0x0800   # MOUSEEVENTF_WHEEL
      }
      'key' {
        $inp.type = 1   # INPUT_KEYBOARD
        $k = "$($e.k)"
        if ($VK.ContainsKey($k)) {
            $inp.u.ki.wVk = [uint16]$VK[$k]
            $inp.u.ki.dwFlags = if ($e.down -eq $false) { 0x0002 } else { 0x0000 }  # KEYUP
        }
        elseif ($k.Length -eq 1) {
            # printable char: send as UNICODE scan code. Sending the codepoint
            # as a virtual key would be wrong - e.g. 'a' is 0x61 = VK_NUMPAD6,
            # not VK_A, so typing would produce numpad keys and nothing would
            # appear. KEYEVENTF_UNICODE (0x0004) makes wScan the codepoint.
            $inp.u.ki.wScan = [uint16][int]$k[0]
            $inp.u.ki.dwFlags = if ($e.down -eq $false) { 0x0006 } else { 0x0004 }
        }
      }
    }
    $buf[$i] = $inp; $i++
  }
  return [MTInput]::SendInput([uint32]$buf.Length, $buf, [Runtime.InteropServices.Marshal]::SizeOf([MTInput+INPUT]))
}

# ---------- crypto: server stores sha256(key) and uses it as the HMAC key ----------
$SHA = [Security.Cryptography.SHA256]::Create()
function KeyHash($k){ return ([BitConverter]::ToString($SHA.ComputeHash([Text.Encoding]::UTF8.GetBytes($k))) -replace '-','').ToLower() }
$KH = KeyHash $cfg.key
function Sign([byte[]]$body){
    $h = New-Object Security.Cryptography.HMACSHA256
    $h.Key = [Text.Encoding]::UTF8.GetBytes($KH)
    return ([BitConverter]::ToString($h.ComputeHash($body)) -replace '-','').ToLower()
}

# ---------- screen capture (GDI+ via CopyFromScreen, JPEG encoded) ----------
function Capture-Jpeg([int]$quality=55){
    $b = [Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object Drawing.Bitmap($b.Width, $b.Height)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [Drawing.Point]::Empty, $b.Size)
    $ms = New-Object IO.MemoryStream
    $jpg = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
    $p = New-Object Drawing.Imaging.EncoderParameters(1)
    $p.Param[0] = New-Object Drawing.Imaging.EncoderParameter([Drawing.Imaging.Encoder]::Quality, [int64]$quality)
    $bmp.Save($ms, $jpg, $p)
    $bmp.Dispose(); $g.Dispose(); $ms.Close()
    return $ms.ToArray()
}

# ---------- metrics ----------
function Get-Metrics {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $mem = 100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100)
    $drive = if ($cfg.drive) { $cfg.drive } else { 'C:' }
    $sys = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.DeviceID -eq $drive }
    $disk = if ($sys) { 100 - ($sys.FreeSpace / $sys.Size * 100) } else { $null }

    $base = Join-Path $env:LOCALAPPDATA "MetaQuotes\Terminal"
    $terms = @()
    if (Test-Path $base) {
        foreach ($inst in Get-ChildItem $base -Directory -EA SilentlyContinue) {
            foreach ($exe in 'terminal64.exe','terminal.exe') {
                $p = Join-Path $inst.FullName $exe
                if (Test-Path $p) {
                    $n = [IO.Path]::GetFileNameWithoutExtension($exe)
                    $proc = Get-Process -Name $n -EA SilentlyContinue | Where-Object { $_.Path -like "*$($inst.Name)*" }
                    $terms += [pscustomobject]@{
                        name=$inst.Name; kind=(if($exe -eq 'terminal64.exe'){'MT5'}else{'MT4'});
                        running=[bool]$proc; memory_mb=if($proc){[math]::Round($proc.WorkingSet64/1MB)}else{0} }
                }
            }
        }
    }
    return [pscustomobject]@{
        ts=Now-Epoch
        cpu=[math]::Round($cpu,1); mem=[math]::Round($mem,1); disk=[math]::Round($disk,1)
        drive=$drive; uptime_min=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalMinutes)
        hostname=$env:COMPUTERNAME; os=$os.Caption
        session_id=$SessionId; role=$Role
        mt_terminals=$terms; mt5_accounts=@()
    }
}

# ---------- transport ----------
function Post-Signed([string]$path, [byte[]]$body, [string]$ct='application/octet-stream'){
    $h = @{ 'X-Agent-ID'=$cfg.agent_id; 'X-Signature'=(Sign $body); 'Content-Type'=$ct }
    # Server pakai self-signed cert: pin thumbprint saat pertama kali terhubung
    # sehingga MITM dengan cert berbeda akan ditolak. Kalau server pakai sertifikat
    # asli (Let's Encrypt / domain), hapus blok ini dan biarkan trust store OS verifikasi.
    if (-not [Net.ServicePointManager]::ServerCertificateValidationCallback) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($s, $cert, $chain, $errs)
            $thumb = $cert.GetCertHashString()
            if (-not $script:PinnedThumb) { $script:PinnedThumb = $thumb; return $true }
            return ($thumb -eq $script:PinnedThumb)
        }
    }
    try { return Invoke-RestMethod -Uri ($cfg.server_url.TrimEnd('/')+$path) -Method Post -Headers $h -Body $body -TimeoutSec 12 }
    catch { Write-Host "post $path failed: $($_.Exception.Message)"; return $null }
}
function Post-Json([string]$path, $obj){
    $j = $obj | ConvertTo-Json -Depth 6 -Compress
    return Post-Signed $path ([Text.Encoding]::UTF8.GetBytes($j)) 'application/json'
}

# ---------- command execution (whitelist only) ----------
function Invoke-Queued($cmd){
    $action = $cmd.action; $a = $cmd.args
    $res = [pscustomobject]@{ ok=$false; action=$action; output='' }
    try {
        switch ($action) {
            'screenshot'   { $res.ok=$true; $res.output='captured' }
            'restart_mt5'  {
                Get-Process terminal64,terminal -EA SilentlyContinue | Stop-Process -Force
                Start-Sleep -Seconds 6
                $exes = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'MetaQuotes\Terminal') -Recurse -Filter 'terminal64.exe' -EA SilentlyContinue
                if ($exes) { Start-Process $exes[0].FullName; $res.ok=$true; $res.output='restarted' }
                else { $res.output='no MT5 terminal installed (in session 0 this is the trader profile - run from the RDP session)' }
            }
            'kill_process' {
                $p = Get-Process -Name $a.name -EA SilentlyContinue
                if ($p) { $p | Stop-Process -Force; $res.ok=$true; $res.output="killed $($a.name)" }
                else { $res.output="$($a.name) not running" }
            }
            'run_command'  {
                $out = cmd /c $a.cmd 2>&1 | Out-String
                $res.ok=$true; $res.output=$out.Trim()
            }
            'reboot'       { $res.ok=$true; $res.output='reboot scheduled'; shutdown /r /t 5 }
            default        { $res.output="unknown action $action" }
        }
    } catch { $res.output = $_.Exception.Message }
    return $res
}

# ---------- main loop ----------
$beat = if ($cfg.interval_sec) { [int]$cfg.interval_sec } else { 30 }
if ($beat -lt 5) { $beat = 5 }
$shotEvery = if ($cfg.screenshot_sec) { [int]$cfg.screenshot_sec } else { 1 }
if ($shotEvery -lt 1) { $shotEvery = 1 }   # fast frames: input only feels live when the screen keeps up
$lastShot = [int64]0
$inputFast = [int64]1      # tight poll while input may be queued
$lastInputPoll = [int64]0
$CanSeeScreen = ($SessionId -ne 0)   # session 0 cannot capture or inject input
$LogFile = Join-Path $here ('agent-{0}.log' -f $Role)
"mtmon agent [{0}] session {1} pid {2} -> {3} | beat {4}s | shot {5}s" -f $Role, $SessionId, $PID, $cfg.server_url, $beat, $shotEvery | Out-File $LogFile -Append
if (-not $CanSeeScreen) { "session 0: heartbeat+metrics only. Screen/input resume when a trader logs in (logon task)." | Out-File $LogFile -Append }
function Log($msg){ "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg | Out-File $LogFile -Append }

# The tight 300ms loop is only for input polling. Metrics cost 3 WMI queries
# each, so posting them every iteration would hammer the box for no gain -
# keep them on the normal beat interval.
$lastBeat = [int64]0

while ($true) {
    $now = Now-Epoch
    try {
        if (($now - $lastBeat) -ge $beat) {
            $lastBeat = $now
            $m = Get-Metrics
            Post-Json '/api/ingest' $m | Out-Null
            Log ("cpu={0} mem={1} disk={2} terminals={3}" -f $m.cpu, $m.mem, $m.disk, $m.mt_terminals.Count)
        }

        # passive frame: skip while an operator is driving, the input branch
        # below captures on demand at higher quality
        if ($CanSeeScreen -and -not $script:ControlActive -and (($now - $lastShot) -ge $shotEvery)) {
            try {
                $jpg = Capture-Jpeg ([int]$cfg.jpeg_quality)
                Post-Signed ('/api/screenshots/' + $cfg.agent_id) $jpg 'image/jpeg' | Out-Null
                $lastShot = $now
            } catch { Log "screenshot failed: $($_.Exception.Message)" }
        }

        # remote input: drain fast so mouse movement feels responsive (interactive only)
        if ($CanSeeScreen -and (($now - $lastInputPoll) -ge $inputFast)) {
            try {
                $ir = Post-Json ('/api/input/' + $cfg.agent_id + '/poll') @{ agent_id=$cfg.agent_id }
                $script:ControlActive = [bool]$ir.control
                if ($ir -and $ir.events -and $ir.events.Count -gt 0) {
                    Send-InputEvents $ir.events | Out-Null
                    # we injected input -> the screen changed. Capture right now
                    # at higher quality so MT5 text stays readable while driving.
                    try {
                        $q = if ($script:ControlActive) { 78 } else { [int]$cfg.jpeg_quality }
                        $jpg = Capture-Jpeg $q
                        Post-Signed ('/api/screenshots/' + $cfg.agent_id) $jpg 'image/jpeg' | Out-Null
                        $lastShot = $now
                    } catch { }
                }
                # back off when the queue is empty - but stay tight while an
                # operator is actually holding control (flag comes from server)
                $inputFast = if ($script:ControlActive) { 1 } elseif ($ir -and $ir.remaining -gt 0) { 1 } else { 3 }
            } catch { }
            $lastInputPoll = $now
        }

        # queued commands (lower frequency than input)
        if (($now % $beat) -lt 2) {
            $r = Post-Json '/api/commands/poll' @{ agent_id=$cfg.agent_id }
            if ($r -and $r.pending) {
                Log "command $($r.id): $($r.action)"
                $out = Invoke-Queued $r
                Post-Json '/api/commands/done' @{ id=$r.id; result=$out } | Out-Null
            }
        }
    } catch { Log "loop error: $($_.Exception.Message)" }
    Start-Sleep -Milliseconds 300
}
