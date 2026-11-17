<#
  revoke.ps1  -  Windows intruder eviction (portable fallback for the Go `revoke`).

  Three-stage sequence:
    1. Log off every interactive/RDP session except your own, and close inbound
       SMB sessions (file-share footholds).
    2. Rotate local (and domain, on a DC) passwords for human accounts; built-in,
       service and SPN accounts are left alone.
    3. Log sessions off again, dropping anything re-established during rotation.

  Standalone paste-able rewrite of cmd/revoke (Windows behavior). Run elevated.

    .\revoke.ps1                 # full sequence, preserves your session
    .\revoke.ps1 -NoRotate       # only revoke sessions

  Flags: -Out -IncludeSelf -IncludeRoot -Domain -Length -NoSymbols -Deny -NoRotate
#>
[CmdletBinding()]
param(
  [string]$Out,
  [switch]$IncludeSelf,
  [bool]$IncludeRoot = $true,
  [bool]$Domain = $true,
  [int]$Length = 20,
  [switch]$NoSymbols,
  [string]$Deny = "",
  [switch]$NoRotate
)
$ErrorActionPreference = 'Continue'

function Ts { (Get-Date).ToString('HH:mm:ss') }
function Info($m){ Write-Host ("[{0}] [*] {1}" -f (Ts), $m) -ForegroundColor Cyan }
function Good($m){ Write-Host ("[{0}] [+] {1}" -f (Ts), $m) -ForegroundColor Green }
function Warn($m){ Write-Host ("[{0}] [!] {1}" -f (Ts), $m) -ForegroundColor Yellow }
function Err ($m){ Write-Host ("[{0}] [-] {1}" -f (Ts), $m) -ForegroundColor Red }

$Host_ = $env:COMPUTERNAME
$Self  = ($env:USERNAME).ToLower()

function Is-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Is-Elevated)) { Err "must run as root/Administrator"; exit 1 }

if (-not $Out) {
  $base = if ($env:ProgramData) { $env:ProgramData } elseif ($env:SystemDrive) { "$env:SystemDrive\" } else { 'C:\' }
  $secretDir = Join-Path $base 'wrccdc'
  New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
  $Out = Join-Path $secretDir "$Host_-revoke_passwords.txt"
}

$DenyList = @(
  'root','daemon','bin','sys','sync','games','man','lp','mail','news','uucp',
  'proxy','backup','list','irc','gnats','nobody','systemd-network',
  'systemd-resolve','systemd-timesync','messagebus','syslog','_apt','tss',
  'uuidd','tcpdump','landscape','pollinate','sshd','systemd-coredump','lxd',
  'dnsmasq','ntp','chrony','mysql','postgres','redis','mongodb','mongod',
  'nginx','www-data','apache','httpd','named','bind','git','gitea','forgejo',
  'nobody4','ftp','vmail','dovecot','dovenull','postfix','clamav','amavis',
  'haproxy','memcache','rabbitmq','elasticsearch','grafana','prometheus',
  'docker','containerd','nixbld','snapd','krbtgt','guest','defaultaccount',
  'wdagutilityaccount','sshd_server','healthmailbox'
)
$DenyExtra = @()
if ($Deny) { $DenyExtra = $Deny.Split(',') | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } }
function Is-ServiceAccount($name) {
  $ln = $name.Trim().ToLower()
  if ($DenyList -contains $ln) { return $true }
  if ($DenyExtra -contains $ln) { return $true }
  if ($ln -like 'nixbld*' -or $ln -like 'svc-*' -or $ln -like 'svc_*' -or $ln -like '_*') { return $true }
  return $false
}

# --------------------------------------------------- password generation ---
$Lower='abcdefghijkmnopqrstuvwxyz'; $Upper='ABCDEFGHJKLMNPQRSTUVWXYZ'
$Digits='23456789'; $Syms='!@#$%^*()-_=+[]{}'
$RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Rand-Int([int]$max) {
  $limit = 256 - (256 % $max); $b = New-Object 'byte[]' 1
  while ($true) { $RNG.GetBytes($b); if ($b[0] -lt $limit) { return ($b[0] % $max) } }
}
function Pick([string]$set) { $set[(Rand-Int $set.Length)] }
function Generate([int]$len, [bool]$useSym) {
  if ($len -lt 8) { $len = 8 }
  $pool = $Lower + $Upper + $Digits; $req = @($Lower, $Upper, $Digits)
  if ($useSym) { $pool += $Syms; $req += $Syms }
  $out = New-Object System.Collections.Generic.List[char]
  foreach ($c in $req) { $out.Add((Pick $c)) }
  while ($out.Count -lt $len) { $out.Add((Pick $pool)) }
  for ($i = $out.Count - 1; $i -gt 0; $i--) { $j = Rand-Int ($i+1); $t=$out[$i]; $out[$i]=$out[$j]; $out[$j]=$t }
  -join $out
}

# ------------------------------------------------- stage 1/3: revoke --------
function Get-MySessionId {
  try { return (Get-Process -Id $PID).SessionId } catch { return -1 }
}
$sessionStates = @('Active','Disc','Listen','Conn','ConnQ','Shadow','Down','Idle')

function Revoke-Sessions([int]$stage) {
  Info "stage ${stage}: revoking sessions"
  $myId = Get-MySessionId
  $raw = (& query session 2>$null)
  if (-not $raw) { $raw = (& qwinsta 2>$null) }
  if (-not $raw) { Warn "could not enumerate sessions (query session)" }
  else {
    foreach ($line in $raw) {
      $trim = $line.TrimStart()
      $isCurrent = $trim.StartsWith('>')
      $trim = $trim.TrimStart('>')
      $f = $trim -split '\s+' | Where-Object { $_ }
      if ($f.Count -lt 2) { continue }
      $stateIdx = -1
      for ($i=0; $i -lt $f.Count; $i++) { if ($sessionStates -contains $f[$i]) { $stateIdx = $i; break } }
      if ($stateIdx -lt 1) { continue }
      $idField = $f[$stateIdx-1]
      $id = 0; if (-not [int]::TryParse($idField, [ref]$id)) { continue }
      $state = $f[$stateIdx]
      $user = ''
      if ($stateIdx-1 -ge 2) { $user = $f[$stateIdx-2] }
      if ($state -eq 'Listen' -or $id -eq 0 -or $id -eq 65536) { continue }
      if ($isCurrent -or $id -eq $myId) { Good "kept own session id=$id ($user)"; continue }
      if (-not $IncludeSelf -and $myId -lt 0 -and $user -and ($user.ToLower() -eq $Self)) {
        Good "kept session id=$id for current user (own id unknown)"; continue }
      try { & logoff $id 2>$null; Good "logged off session id=$id ($user)" }
      catch { Warn "logoff ${id}: $($_.Exception.Message)" }
    }
  }
  # Drop inbound SMB sessions.
  try { Close-SmbSession -Force -ErrorAction Stop; Good "closed inbound SMB sessions" }
  catch {
    try { & net session /delete /y 2>$null | Out-Null; Good "closed inbound SMB sessions (net session)" } catch {}
  }
}

# ------------------------------------------------- stage 2: rotate ----------
function Rotate-Passwords {
  Info "stage 2: rotating passwords (local$([string]::Format('{0}', $(if($Domain){' + domain if DC'}else{''})) ))"
  $useSym = -not $NoSymbols
  $creds = New-Object System.Collections.Generic.List[object]
  $skipped = New-Object System.Collections.Generic.List[string]

  $localUsers = @()
  try { $localUsers = Get-LocalUser -ErrorAction Stop } catch { Err "Get-LocalUser: $($_.Exception.Message)" }
  foreach ($u in $localUsers) {
    $rid = ($u.SID.Value -split '-')[-1]; $reason = ''
    switch ($rid) {
      '501' { $reason = 'built-in system account' }
      '503' { $reason = 'built-in system account' }
      '504' { $reason = 'built-in system account' }
      '500' { if (-not $IncludeRoot) { $reason = 'built-in Administrator' } }
    }
    if (-not $reason) {
      if (-not $u.Enabled) { $reason = 'disabled account' }
      elseif ($u.Name.ToLower() -eq $Self -and -not $IncludeSelf) { $reason = 'current user' }
      elseif (Is-ServiceAccount $u.Name) { $reason = 'service/system account' }
    }
    if ($reason) { $skipped.Add("$($u.Name) ($reason)") | Out-Null; continue }
    $pw = Generate $Length $useSym
    try {
      Set-LocalUser -Name $u.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
      Good ("local {0,-20} changed" -f $u.Name)
      $creds.Add([pscustomobject]@{ scope='local'; user=$u.Name; password=$pw; status='changed' })
    } catch {
      Err ("local {0,-20} error: {1}" -f $u.Name, $_.Exception.Message)
      $creds.Add([pscustomobject]@{ scope='local'; user=$u.Name; password=''; status="error: $($_.Exception.Message)" })
    }
  }

  # Domain stage.
  $isDC = $false; try { $r=(Get-CimInstance Win32_ComputerSystem).DomainRole; $isDC = ($r -eq 4 -or $r -eq 5) } catch {}
  if ($Domain -and $isDC -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      foreach ($u in (Get-ADUser -Filter * -Properties servicePrincipalName,Enabled)) {
        $sam=$u.SamAccountName; $low=$sam.ToLower(); $reason=''
        if ($low -eq 'krbtgt') { $reason='krbtgt service account' }
        elseif ($u.servicePrincipalName) { $reason='has servicePrincipalName' }
        elseif (-not $u.Enabled) { $reason='disabled account' }
        elseif ($low -eq 'administrator' -and -not $IncludeRoot) { $reason='domain Administrator' }
        elseif ($low -eq $Self -and -not $IncludeSelf) { $reason='current user' }
        elseif (Is-ServiceAccount $sam) { $reason='service/system account' }
        if ($reason) { $skipped.Add("$sam (domain: $reason)") | Out-Null; continue }
        $pw = Generate $Length $useSym
        try {
          Set-ADAccountPassword -Identity $sam -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
          Good ("domain {0,-20} changed" -f $sam)
          $creds.Add([pscustomobject]@{ scope='domain'; user=$sam; password=$pw; status='changed' })
        } catch {
          Err ("domain {0,-20} error: {1}" -f $sam, $_.Exception.Message)
          $creds.Add([pscustomobject]@{ scope='domain'; user=$sam; password=''; status="error: $($_.Exception.Message)" })
        }
      }
    } catch { Err "Get-ADUser: $($_.Exception.Message)" }
  }

  # Write 0600-equivalent record.
  $dir = Split-Path -Parent $Out
  if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# WRCCDC password rotation record')
  [void]$sb.AppendLine("# host=$Host_ os=windows time=$((Get-Date).ToString('o'))")
  [void]$sb.AppendLine('# KEEP THIS FILE SECRET. Record it off-box, then delete.')
  [void]$sb.AppendLine('scope,username,password,status')
  foreach ($c in ($creds | Sort-Object scope, user)) { [void]$sb.AppendLine("$($c.scope),$($c.user),$($c.password),$($c.status)") }
  if ($skipped.Count -gt 0) {
    [void]$sb.AppendLine(''); [void]$sb.AppendLine('# skipped (left intentionally alone):')
    foreach ($s in $skipped) { [void]$sb.AppendLine("# - $s") }
  }
  Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
  & icacls $Out /inheritance:r /grant:r '*S-1-5-32-544:F' /grant:r '*S-1-5-18:F' | Out-Null
  Good "credentials written to $Out (admins/SYSTEM only)"
}

# ------------------------------------------------------------- main run -----
Info "host=$Host_ os=windows  -  stage 1: revoking sessions"
Revoke-Sessions 1
if (-not $NoRotate) { Rotate-Passwords } else { Info "stage 2 skipped (-NoRotate)" }
Revoke-Sessions 3
Write-Host ""
Write-Host "Done. Verify no unexpected sessions remain and that the credential record is stored off-box."
