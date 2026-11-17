<#
  enum.ps1  -  Windows host enumeration (portable fallback for the Go `enum`).

  Collects systeminfo, IP config, listening ports and owning PIDs, routes, ARP,
  processes, local users/admins, sessions, scheduled tasks, shares, running
  services, installed applications and firewall posture into one report.
  Standalone paste-able rewrite of cmd/enum (Windows behavior).

    .\enum.ps1 -Out C:\enum.txt

  A full run can take ~30-60 seconds (systeminfo + several queries).
#>
[CmdletBinding()]
param(
  [string]$Out
)
$ErrorActionPreference = 'Continue'

function Ts { (Get-Date).ToString('HH:mm:ss') }
function Info($m){ Write-Host ("[{0}] [*] {1}" -f (Ts), $m) -ForegroundColor Cyan }
function Good($m){ Write-Host ("[{0}] [+] {1}" -f (Ts), $m) -ForegroundColor Green }
function Warn($m){ Write-Host ("[{0}] [!] {1}" -f (Ts), $m) -ForegroundColor Yellow }

$Host_ = $env:COMPUTERNAME
if (-not $Out) { $Out = Join-Path $env:TEMP "$Host_-enum.txt" }

function Is-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

Info "host=$Host_ os=windows"
if (-not (Is-Elevated)) { Warn "not running as Administrator: some sections will be incomplete" }

$sb = New-Object System.Text.StringBuilder
function Section($title, $body) {
  if (-not $body) { $body = '(no output)' }
  [void]$sb.AppendLine('==================================================')
  [void]$sb.AppendLine($title)
  [void]$sb.AppendLine('--------------------------------------------------')
  [void]$sb.AppendLine(($body | Out-String).TrimEnd())
  [void]$sb.AppendLine('')
}
function RunExe($title, $exe, $argList) {
  if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { Section $title "($exe not available)"; return }
  try { $o = & $exe @argList 2>&1 | Out-String } catch { $o = $_.Exception.Message }
  Section $title $o
}
function RunPS($title, $sblock) {
  try { $o = (& $sblock 2>&1 | Out-String) } catch { $o = $_.Exception.Message }
  Section $title $o
}

# --- Host summary ---
Section 'Host' ("hostname: {0}`r`nos: windows`r`ncollected: {1}" -f $Host_, (Get-Date).ToString('o'))

# --- cmd-style sections (mirror enum_windows.go) ---
RunExe 'OS version'                    'cmd'        @('/c','ver')
RunExe 'System info'                   'systeminfo' @()
RunExe 'IP configuration'              'ipconfig'   @('/all')
RunExe 'Listening ports & owning PIDs' 'netstat'    @('-ano')
RunExe 'Routing table'                 'route'      @('print')
RunExe 'ARP cache'                     'arp'        @('-a')
RunExe 'Running processes'             'tasklist'   @('/v')
RunExe 'Local users'                   'net'        @('user')
RunExe 'Administrators group'          'net'        @('localgroup','administrators')
RunExe 'Active sessions'               'query'      @('session')
RunExe 'Scheduled tasks'               'schtasks'   @('/query','/fo','LIST','/v')
RunExe 'Shares'                        'net'        @('share')

# --- richer PowerShell sections ---
RunPS 'Running services' {
  Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object Name |
    Format-Table -AutoSize Name,DisplayName | Out-String -Width 4096
}
RunPS 'Installed applications' {
  $p = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
    Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName |
    Format-Table -AutoSize | Out-String -Width 4096
}
RunPS 'Firewall profiles' {
  Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
    Out-String -Width 4096
}
RunPS 'Listening TCP (owning process)' {
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress,LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object LocalPort | Format-Table -AutoSize | Out-String -Width 4096
}
RunPS 'Local administrators (detailed)' {
  Get-LocalGroupMember -Group 'Administrators' | Format-Table Name,ObjectClass,PrincipalSource |
    Out-String -Width 4096
}

$dir = Split-Path -Parent $Out
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
try { & icacls $Out /inheritance:r /grant:r '*S-1-5-32-544:F' /grant:r '*S-1-5-18:F' | Out-Null } catch {}
Good "enumeration written to $Out"
