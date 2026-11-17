<#
  rotatepw.ps1  -  Windows password rotation (portable fallback for the Go
  `rotatepw`). Rotates enabled local users (and, on a domain controller with the
  ActiveDirectory module, domain users) while leaving built-in/service/SPN
  accounts untouched, and records new credentials to a locked-down file.

  Standalone paste-able rewrite of cmd/rotatepw (Windows behavior). Run elevated.
  Use -DryRun to preview without changing anything.

    .\rotatepw.ps1                 # local + domain (SPN/service auto-skipped)
    .\rotatepw.ps1 -Domain:$false  # local accounts only
    .\rotatepw.ps1 -DryRun

  Flags mirror the Go tool: -Out -Length -NoSymbols -IncludeRoot -IncludeSelf
  -Domain -Deny -DryRun.
#>
[CmdletBinding()]
param(
  [string]$Out,
  [int]$Length = 20,
  [switch]$NoSymbols,
  [bool]$IncludeRoot = $true,
  [switch]$IncludeSelf,
  [bool]$Domain = $true,
  [string]$Deny = "",
  [switch]$DryRun
)
$ErrorActionPreference = 'Continue'

# ----------------------------------------------------------------- logging ---
function Ts { (Get-Date).ToString('HH:mm:ss') }
function Info($m){ Write-Host ("[{0}] [*] {1}" -f (Ts), $m) -ForegroundColor Cyan }
function Good($m){ Write-Host ("[{0}] [+] {1}" -f (Ts), $m) -ForegroundColor Green }
function Warn($m){ Write-Host ("[{0}] [!] {1}" -f (Ts), $m) -ForegroundColor Yellow }
function Err ($m){ Write-Host ("[{0}] [-] {1}" -f (Ts), $m) -ForegroundColor Red }

$Host_ = $env:COMPUTERNAME
$Self  = ($env:USERNAME).ToLower()

# Secret dir: %ProgramData%\wrccdc.
if (-not $Out) {
  $base = if ($env:ProgramData) { $env:ProgramData } elseif ($env:SystemDrive) { "$env:SystemDrive\" } else { 'C:\' }
  $secretDir = Join-Path $base 'wrccdc'
  New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
  $Out = Join-Path $secretDir "$Host_-new_passwords.txt"
}

# ------------------------------------------------- service/system deny list ---
# Mirrors serviceAccountDeny in internal/common/rotate.go.
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
$Lower  = 'abcdefghijkmnopqrstuvwxyz'  # no l
$Upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'   # no I, O
$Digits = '23456789'                   # no 0, 1
$Syms   = '!@#$%^*()-_=+[]{}'
$RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Rand-Int([int]$max) {
  $limit = 256 - (256 % $max)
  $b = New-Object 'byte[]' 1
  while ($true) {
    $RNG.GetBytes($b)
    if ($b[0] -lt $limit) { return ($b[0] % $max) }
  }
}
function Pick([string]$set) { $set[(Rand-Int $set.Length)] }
function Generate([int]$len, [bool]$useSym) {
  if ($len -lt 8) { $len = 8 }
  $pool = $Lower + $Upper + $Digits
  $req  = @($Lower, $Upper, $Digits)
  if ($useSym) { $pool += $Syms; $req += $Syms }
  $out = New-Object System.Collections.Generic.List[char]
  foreach ($c in $req) { $out.Add((Pick $c)) }
  while ($out.Count -lt $len) { $out.Add((Pick $pool)) }
  for ($i = $out.Count - 1; $i -gt 0; $i--) {
    $j = Rand-Int ($i + 1); $t = $out[$i]; $out[$i] = $out[$j]; $out[$j] = $t
  }
  -join $out
}

function Is-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

# ------------------------------------------------------------------- main ---
Info "host=$Host_ os=windows (dry-run=$($DryRun.IsPresent))"
if (-not (Is-Elevated) -and -not $DryRun) {
  Err "must run elevated (Administrator) to change passwords (use -DryRun to preview)"
  exit 1
}

$creds   = New-Object System.Collections.Generic.List[object]
$skipped = New-Object System.Collections.Generic.List[string]
$useSym  = -not $NoSymbols

function Add-Skip($name, $reason) {
  $skipped.Add("$name ($reason)") | Out-Null
  Info "skip: $name ($reason)"
}

# --- Local users ---
$localUsers = @()
try { $localUsers = Get-LocalUser -ErrorAction Stop } catch {
  Err "Get-LocalUser: $($_.Exception.Message)"
}
foreach ($u in $localUsers) {
  $rid = ($u.SID.Value -split '-')[-1]
  $reason = ''
  switch ($rid) {
    '501' { $reason = 'built-in system account' }
    '503' { $reason = 'built-in system account' }
    '504' { $reason = 'built-in system account' }
    '500' { if (-not $IncludeRoot) { $reason = 'built-in Administrator (use -IncludeRoot to rotate)' } }
  }
  if (-not $reason) {
    if (-not $u.Enabled) { $reason = 'disabled account' }
    elseif ($u.Name.ToLower() -eq $Self -and -not $IncludeSelf) { $reason = 'current user (use -IncludeSelf to override)' }
    elseif (Is-ServiceAccount $u.Name) { $reason = 'service/system account' }
  }
  if ($reason) { Add-Skip $u.Name $reason; continue }

  $pw = Generate $Length $useSym
  if ($DryRun) {
    Info ("local {0,-20} would change" -f $u.Name)
    $creds.Add([pscustomobject]@{ scope='local'; user=$u.Name; password=$pw; status='dry-run' }); continue
  }
  try {
    Set-LocalUser -Name $u.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
    Good ("local {0,-20} changed" -f $u.Name)
    $creds.Add([pscustomobject]@{ scope='local'; user=$u.Name; password=$pw; status='changed' })
  } catch {
    Err ("local {0,-20} error: {1}" -f $u.Name, $_.Exception.Message)
    $creds.Add([pscustomobject]@{ scope='local'; user=$u.Name; password=''; status="error: $($_.Exception.Message)" })
  }
}

# --- Domain users (only on a DC with the AD module) ---
function Is-DomainController {
  try { $r = (Get-CimInstance Win32_ComputerSystem).DomainRole; return ($r -eq 4 -or $r -eq 5) } catch { return $false }
}
function AD-Available { [bool](Get-Module -ListAvailable -Name ActiveDirectory) }

if ($Domain -and (Is-DomainController) -and (AD-Available)) {
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adUsers = Get-ADUser -Filter * -Properties servicePrincipalName,Enabled
    foreach ($u in $adUsers) {
      $sam = $u.SamAccountName; $low = $sam.ToLower()
      $reason = ''
      if ($low -eq 'krbtgt') { $reason = 'krbtgt service account' }
      elseif ($u.servicePrincipalName) { $reason = 'has servicePrincipalName (service account)' }
      elseif (-not $u.Enabled) { $reason = 'disabled account' }
      elseif ($low -eq 'administrator' -and -not $IncludeRoot) { $reason = 'domain Administrator (use -IncludeRoot to rotate)' }
      elseif ($low -eq $Self -and -not $IncludeSelf) { $reason = 'current user (use -IncludeSelf to override)' }
      elseif (Is-ServiceAccount $sam) { $reason = 'service/system account' }
      if ($reason) { Add-Skip $sam "domain: $reason"; continue }

      $pw = Generate $Length $useSym
      if ($DryRun) {
        Info ("domain {0,-20} would change" -f $sam)
        $creds.Add([pscustomobject]@{ scope='domain'; user=$sam; password=$pw; status='dry-run' }); continue
      }
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
} elseif ($Domain) {
  Add-Skip 'domain rotation' '(not a DC or ActiveDirectory module unavailable)'
}

# ------------------------------------------------------- write cred file ---
$changed = ($creds | Where-Object { $_.status -eq 'changed' -or $_.status -eq 'dry-run' }).Count
$errors  = ($creds | Where-Object { $_.status -ne 'changed' -and $_.status -ne 'dry-run' }).Count

if (-not $DryRun) {
  $dir = Split-Path -Parent $Out
  if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# WRCCDC password rotation record')
  [void]$sb.AppendLine("# host=$Host_ os=windows time=$((Get-Date).ToString('o'))")
  [void]$sb.AppendLine('# KEEP THIS FILE SECRET. Record it off-box, then delete.')
  [void]$sb.AppendLine('scope,username,password,status')
  foreach ($c in ($creds | Sort-Object scope, user)) {
    [void]$sb.AppendLine("$($c.scope),$($c.user),$($c.password),$($c.status)")
  }
  if ($skipped.Count -gt 0) {
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('# skipped (left intentionally alone):')
    foreach ($s in $skipped) { [void]$sb.AppendLine("# - $s") }
  }
  Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
  # Lock down: strip inheritance, grant only Administrators + SYSTEM.
  & icacls $Out /inheritance:r /grant:r '*S-1-5-32-544:F' /grant:r '*S-1-5-18:F' | Out-Null
  Good "credentials written to $Out (admins/SYSTEM only)  -  record off-box then delete"
}

Write-Host ""
Write-Host ("Summary: {0} accounts changed, {1} skipped, {2} errors" -f $changed, $skipped.Count, $errors)
if ($errors -gt 0) { exit 1 }
