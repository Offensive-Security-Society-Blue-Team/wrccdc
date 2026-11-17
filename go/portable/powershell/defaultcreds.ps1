<#
  defaultcreds.ps1  -  rotate stock service passwords (portable fallback for the Go
  `defaultcreds`, Windows behavior). Rotates default/known credentials for
  MySQL/MariaDB, WordPress and Gitea so an attacker who memorized the stock
  passwords is locked out. Each service is best-effort: a missing tool/config is
  reported, not fatal.

    .\defaultcreds.ps1 -DryRun
    .\defaultcreds.ps1 -GiteaAdmin giteaadmin
    .\defaultcreds.ps1 -Services mysql -MysqlAll -MysqlPass 'oldRootPw'

  Flags mirror the Go tool: -Services -Out -Length -DryRun
    -MysqlBin -MysqlUser -MysqlPass -MysqlHost -MysqlAll
    -WpPath -WpAdmin  -GiteaBin -GiteaConfig -GiteaAdmin
#>
[CmdletBinding()]
param(
  [string]$Services = 'mysql,wordpress,gitea',
  [string]$Out,
  [int]$Length = 24,
  [switch]$DryRun,
  [string]$MysqlBin = '',
  [string]$MysqlUser = 'root',
  [string]$MysqlPass = '',
  [string]$MysqlHost = '127.0.0.1',
  [switch]$MysqlAll,
  [string]$WpPath = '',
  [string]$WpAdmin = 'admin',
  [string]$GiteaBin = '',
  [string]$GiteaConfig = '',
  [string]$GiteaAdmin = ''
)
$ErrorActionPreference = 'Continue'

function Ts { (Get-Date).ToString('HH:mm:ss') }
function Info($m){ Write-Host ("[{0}] [*] {1}" -f (Ts), $m) -ForegroundColor Cyan }
function Good($m){ Write-Host ("[{0}] [+] {1}" -f (Ts), $m) -ForegroundColor Green }
function Err ($m){ Write-Host ("[{0}] [-] {1}" -f (Ts), $m) -ForegroundColor Red }
function Have($n){ [bool](Get-Command $n -ErrorAction SilentlyContinue) }

$Host_ = $env:COMPUTERNAME
$base = if ($env:ProgramData) { $env:ProgramData } elseif ($env:SystemDrive) { "$env:SystemDrive\" } else { 'C:\' }
$secretDir = Join-Path $base 'wrccdc'
if (-not $Out) { $Out = Join-Path $secretDir "$Host_-default_creds.txt" }

# Alphanumeric password generation (symbols off: SQL/config safe).
$Lower='abcdefghijkmnopqrstuvwxyz'; $Upper='ABCDEFGHJKLMNPQRSTUVWXYZ'; $Digits='23456789'
$RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Rand-Int([int]$max) {
  $limit = 256 - (256 % $max); $b = New-Object 'byte[]' 1
  while ($true) { $RNG.GetBytes($b); if ($b[0] -lt $limit) { return ($b[0] % $max) } }
}
function Pick([string]$set) { $set[(Rand-Int $set.Length)] }
function Generate {
  $len = $Length; if ($len -lt 8) { $len = 8 }
  $pool = $Lower + $Upper + $Digits; $req = @($Lower, $Upper, $Digits)
  $out = New-Object System.Collections.Generic.List[char]
  foreach ($c in $req) { $out.Add((Pick $c)) }
  while ($out.Count -lt $len) { $out.Add((Pick $pool)) }
  for ($i = $out.Count - 1; $i -gt 0; $i--) { $j = Rand-Int ($i+1); $t=$out[$i]; $out[$i]=$out[$j]; $out[$j]=$t }
  -join $out
}

$creds = New-Object System.Collections.Generic.List[object]
function Record($scope,$user,$pw,$status) { $creds.Add([pscustomobject]@{ scope=$scope; user=$user; password=$pw; status=$status }) }
function EscQ($s) { $s -replace "'","''" }
$want = @{}
foreach ($s in $Services.Split(',')) { $t = $s.Trim().ToLower(); if ($t) { $want[$t] = $true } }

Info "host=$Host_ os=windows  -  rotating default service credentials (dry-run=$($DryRun.IsPresent))"

# --------------------------------------------------------------- MySQL -----
function Resolve-Mysql {
  if ($MysqlBin) { return $MysqlBin }
  if (Have 'mysql') { return 'mysql' }
  $cands = @(
    'C:\Program Files\MySQL\MySQL Server *\bin\mysql.exe',
    'C:\Program Files\MariaDB *\bin\mysql.exe',
    'C:\xampp\mysql\bin\mysql.exe',
    'C:\wamp64\bin\mysql\mysql*\bin\mysql.exe',
    'C:\wamp\bin\mysql\mysql*\bin\mysql.exe'
  )
  foreach ($c in $cands) { $m = Get-Item $c -ErrorAction SilentlyContinue | Select-Object -First 1; if ($m) { return $m.FullName } }
  return ''
}
function Mysql-Q($bin, $sql) {
  $args = @('-u', $MysqlUser, '-h', $MysqlHost, '--protocol=TCP', '-N', '-B', '-e', $sql)
  $old = $env:MYSQL_PWD
  if ($MysqlPass) { $env:MYSQL_PWD = $MysqlPass }
  try { $o = & $bin @args 2>&1; $code = $LASTEXITCODE } finally { $env:MYSQL_PWD = $old }
  [pscustomobject]@{ out = ($o | Out-String); code = $code }
}
function Do-Mysql {
  $bin = Resolve-Mysql
  if (-not $bin) { Record 'mysql' '-' '' 'skipped: mysql client not found (install or pass -MysqlBin)'; Err 'mysql - skipped: client not found'; return }
  $r = Mysql-Q $bin 'SELECT 1'
  if ($r.code -ne 0) { Record 'mysql' $MysqlUser '' 'skipped: cannot authenticate'; Err "mysql $MysqlUser skipped: cannot authenticate"; return }
  $sysUsers = @('mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint','mariadb.sys')
  $targets = @()
  if ($MysqlAll) {
    $r2 = Mysql-Q $bin "SELECT CONCAT(user,'\t',host) FROM mysql.user"
    foreach ($line in ($r2.out -split "`r?`n")) {
      $p = $line -split "`t"
      if ($p.Count -ne 2 -or -not $p[0]) { continue }
      if ($sysUsers -contains $p[0].ToLower()) { continue }
      $targets += ("'" + (EscQ $p[0]) + "'@'" + (EscQ $p[1]) + "'")
    }
  } else {
    foreach ($h in @('localhost','127.0.0.1','%')) {
      $e = Mysql-Q $bin ("SELECT 1 FROM mysql.user WHERE user='" + (EscQ $MysqlUser) + "' AND host='" + (EscQ $h) + "'")
      if ($e.out.Trim()) { $targets += ("'" + (EscQ $MysqlUser) + "'@'" + (EscQ $h) + "'") }
    }
    if ($targets.Count -eq 0) { $targets += ("'" + (EscQ $MysqlUser) + "'@'localhost'") }
  }
  foreach ($t in $targets) {
    $pw = Generate
    if ($DryRun) { Record 'mysql' $t $pw 'dry-run'; Good "mysql $t dry-run"; continue }
    $a = Mysql-Q $bin ("ALTER USER $t IDENTIFIED BY '$pw'")
    if ($a.code -ne 0) { $a = Mysql-Q $bin ("SET PASSWORD FOR $t = PASSWORD('$pw')") }
    if ($a.code -eq 0) { Mysql-Q $bin 'FLUSH PRIVILEGES' | Out-Null; Record 'mysql' $t $pw 'changed'; Good "mysql $t changed" }
    else { Record 'mysql' $t '' 'error: alter/set password failed'; Err "mysql $t error" }
  }
}

# ------------------------------------------------------------ WordPress ----
function Wp-Define($text, $key) {
  $m = [regex]::Match($text, "(?i)define\(\s*['""]$key['""]\s*,\s*['""]([^'""]*)['""]")
  if ($m.Success) { return $m.Groups[1].Value }
  return ''
}
function Find-Wp {
  $roots = @('C:\inetpub\wwwroot','C:\xampp\htdocs','C:\wamp64\www','C:\wamp\www')
  foreach ($r in $roots) {
    if (Test-Path (Join-Path $r 'wp-config.php')) { return $r }
    if (Test-Path $r) {
      foreach ($d in (Get-ChildItem $r -Directory -ErrorAction SilentlyContinue)) {
        if (Test-Path (Join-Path $d.FullName 'wp-config.php')) { return $d.FullName }
      }
    }
  }
  return ''
}
function Do-Wordpress {
  $dir = if ($WpPath) { $WpPath } else { Find-Wp }
  if (-not $dir) { Record 'wordpress' '-' '' 'skipped: no wp-config.php found (pass -WpPath)'; Err 'wordpress - skipped: no wp-config.php'; return }
  $pw = Generate; $user = "$WpAdmin @ $dir"
  if ($DryRun) { Record 'wordpress' $user $pw 'dry-run'; Good "wordpress $user dry-run"; return }
  if (Have 'wp') {
    & wp user update $WpAdmin "--user_pass=$pw" "--path=$dir" *> $null
    if ($LASTEXITCODE -eq 0) { Record 'wordpress' $user $pw 'changed (wp-cli)'; Good "wordpress $user changed (wp-cli)"; return }
  }
  $cfg = Join-Path $dir 'wp-config.php'
  $text = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
  if (-not $text) { Record 'wordpress' $user '' 'error: read wp-config.php'; Err 'wordpress error: read wp-config.php'; return }
  $name=Wp-Define $text 'DB_NAME'; $dbuser=Wp-Define $text 'DB_USER'
  $dbpass=Wp-Define $text 'DB_PASSWORD'; $dbhost=Wp-Define $text 'DB_HOST'
  $pm = [regex]::Match($text, "(?m)^\s*\`$table_prefix\s*=\s*['""]([^'""]+)['""]")
  $prefix = if ($pm.Success) { $pm.Groups[1].Value } else { 'wp_' }
  if (-not $name -or -not $dbuser) { Record 'wordpress' $user '' 'error: could not parse DB credentials from wp-config.php'; Err 'wordpress error: parse wp-config.php'; return }
  if (-not $dbhost) { $dbhost = 'localhost' }
  $bin = Resolve-Mysql
  if (-not $bin) { Record 'wordpress' $user '' 'error: wp-cli absent and mysql client not found'; Err 'wordpress error: no mysql client'; return }
  $md5 = [System.Security.Cryptography.MD5]::Create()
  $hash = ([System.BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($pw))) -replace '-','').ToLower()
  $sql = "UPDATE ${prefix}users SET user_pass='$hash' WHERE user_login='$(EscQ $WpAdmin)'"
  $a = @('-u', $dbuser)
  if ($dbhost -ne 'localhost') {
    $hp = $dbhost.Split(':',2); $a += @('-h', $hp[0], '--protocol=TCP')
    if ($hp.Count -eq 2) { $a += @('-P', $hp[1]) }
  }
  $a += @($name, '-e', $sql)
  $old = $env:MYSQL_PWD; if ($dbpass) { $env:MYSQL_PWD = $dbpass }
  try { & $bin @a *> $null; $code = $LASTEXITCODE } finally { $env:MYSQL_PWD = $old }
  if ($code -eq 0) { Record 'wordpress' $user $pw 'changed (db md5)'; Good "wordpress $user changed (db md5)" }
  else { Record 'wordpress' $user '' 'error: db update failed'; Err 'wordpress error: db update' }
}

# --------------------------------------------------------------- Gitea -----
function Resolve-Gitea {
  if ($GiteaBin) { return $GiteaBin }
  if (Have 'gitea') { return 'gitea' }
  foreach ($c in @('C:\gitea\gitea.exe','C:\Program Files\Gitea\gitea.exe')) { if (Test-Path $c) { return $c } }
  return ''
}
function Resolve-GiteaConf {
  if ($GiteaConfig) { return $GiteaConfig }
  foreach ($c in @('C:\gitea\custom\conf\app.ini','C:\Program Files\Gitea\custom\conf\app.ini')) { if (Test-Path $c) { return $c } }
  return ''
}
function Do-Gitea {
  $bin = Resolve-Gitea
  if (-not $bin) { Record 'gitea' '-' '' 'skipped: gitea binary not found (pass -GiteaBin)'; Err 'gitea - skipped: binary not found'; return }
  if (-not $GiteaAdmin) { Record 'gitea' '-' '' 'skipped: no admin username given (pass -GiteaAdmin <user>)'; Err 'gitea - skipped: no admin username'; return }
  $pw = Generate
  if ($DryRun) { Record 'gitea' $GiteaAdmin $pw 'dry-run'; Good "gitea $GiteaAdmin dry-run"; return }
  $conf = Resolve-GiteaConf
  $variants = @(
    @('admin','user','change-password','--username',$GiteaAdmin,'--password',$pw),
    @('admin','change-password','--username',$GiteaAdmin,'--password',$pw)
  )
  $last = ''
  foreach ($base in $variants) {
    $a = $base; if ($conf) { $a += @('--config', $conf) }
    $last = (& $bin @a 2>&1 | Out-String); $code = $LASTEXITCODE
    if ($code -eq 0) { Record 'gitea' $GiteaAdmin $pw 'changed'; Good "gitea $GiteaAdmin changed"; return }
    $low = $last.ToLower()
    if ($low -notmatch 'unknown command|flag provided but not defined|command not found|no help topic') { break }
  }
  $fl = ($last -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
  Record 'gitea' $GiteaAdmin '' "error: $fl"; Err "gitea $GiteaAdmin error"
}

# ------------------------------------------------------------- dispatch ----
if ($want['mysql'] -or $want['mariadb']) { Do-Mysql }
if ($want['wordpress'] -or $want['wp']) { Do-Wordpress }
if ($want['gitea'] -or $want['forgejo']) { Do-Gitea }

foreach ($c in $creds) {
  if ($c.status -eq 'changed' -or $c.status -like 'changed*' -or $c.status -eq 'dry-run') { Good ("{0} {1,-24} {2}" -f $c.scope, $c.user, $c.status) }
  else { Err ("{0} {1,-24} {2}" -f $c.scope, $c.user, $c.status) }
}

if (-not $DryRun) {
  $dir = Split-Path -Parent $Out
  if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# WRCCDC password rotation record')
  [void]$sb.AppendLine("# host=$Host_ os=windows time=$((Get-Date).ToString('o'))")
  [void]$sb.AppendLine('# KEEP THIS FILE SECRET. Record it off-box, then delete.')
  [void]$sb.AppendLine('scope,username,password,status')
  foreach ($c in $creds) { [void]$sb.AppendLine("$($c.scope),$($c.user),$($c.password),$($c.status)") }
  Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
  & icacls $Out /inheritance:r /grant:r '*S-1-5-32-544:F' /grant:r '*S-1-5-18:F' | Out-Null
  Good "credentials written to $Out (admins/SYSTEM only)  -  record off-box then delete"
}
Write-Host ""
Write-Host "Done. Review statuses above; services not installed are reported, not errors."
