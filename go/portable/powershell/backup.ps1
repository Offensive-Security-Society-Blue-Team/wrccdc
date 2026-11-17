<#
  backup.ps1  -  Windows pseudo-snapshot & restore (portable fallback for the Go
  `backup`). Archives the folders red teams wipe or deface (IIS web root, DNS
  zone files, OpenSSH config, XAMPP/WAMP/Apache web roots) and the state of
  running Docker containers, with a sha256-checksummed manifest so restoration is
  verifiable. Standalone paste-able rewrite of cmd/backup (Windows behavior).

    .\backup.ps1 -Mirror E:\backups
    .\backup.ps1 -NoDocker -Paths 'C:\inetpub\wwwroot,C:\Windows\System32\dns'
    .\backup.ps1 -Restore C:\ProgramData\wrccdc\snapshots\HOST-20261111_120000
    .\backup.ps1 -Restore <snapdir> -InPlace -Force

  Folders are stored as .zip (Compress-Archive) with a sidecar files.csv that
  this script's own restore reads, alongside a Go-shaped MANIFEST.json.
#>
[CmdletBinding()]
param(
  [string]$Out,
  [string]$Paths,
  [string]$Add,
  [switch]$NoDocker,
  [string]$Mirror,
  [string]$Restore,
  [switch]$InPlace,
  [switch]$Force
)
$ErrorActionPreference = 'Continue'

function Ts { (Get-Date).ToString('HH:mm:ss') }
function Info($m){ Write-Host ("[{0}] [*] {1}" -f (Ts), $m) -ForegroundColor Cyan }
function Good($m){ Write-Host ("[{0}] [+] {1}" -f (Ts), $m) -ForegroundColor Green }
function Warn($m){ Write-Host ("[{0}] [!] {1}" -f (Ts), $m) -ForegroundColor Yellow }
function Err ($m){ Write-Host ("[{0}] [-] {1}" -f (Ts), $m) -ForegroundColor Red }
function Fatal($m){ Err $m; exit 1 }
function Have($n){ [bool](Get-Command $n -ErrorAction SilentlyContinue) }

$Host_ = $env:COMPUTERNAME
$base = if ($env:ProgramData) { $env:ProgramData } elseif ($env:SystemDrive) { "$env:SystemDrive\" } else { 'C:\' }
$secretDir = Join-Path $base 'wrccdc'
if (-not $Out) { $Out = Join-Path $secretDir 'snapshots' }

function Sha256($file) { try { (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower() } catch { '' } }
function Sanitize($p) {
  $s = ($p -replace '[\\/: ]','_').Trim('_')
  if (-not $s) { $s = 'root' }
  $s
}

function Default-Paths {
  $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
  $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
  $pd = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
  @(
    (Join-Path "$sysDrive\" 'inetpub\wwwroot'),
    (Join-Path "$sysDrive\" 'inetpub'),
    (Join-Path $sysRoot 'System32\dns'),
    (Join-Path $pd 'ssh'),
    (Join-Path "$sysDrive\" 'xampp\htdocs'),
    (Join-Path "$sysDrive\" 'wamp\www'),
    (Join-Path "$sysDrive\" 'Apache24\htdocs')
  )
}

# ============================================================== RESTORE =====
if ($Restore) {
  $snap = $Restore
  $filesCsv = Join-Path $snap 'files.csv'
  if (-not (Test-Path $filesCsv)) { Fatal "no files.csv in $snap (was this snapshot made by backup.ps1?)" }
  if ($InPlace -and -not $Force) { Fatal "in-place restore overwrites live files; re-run with -InPlace -Force" }
  Info "restoring snapshot from $snap"
  foreach ($row in (Import-Csv $filesCsv)) {
    $arc = Join-Path $snap $row.archive
    if (-not (Test-Path $arc)) { Warn "missing archive $($row.archive); skipping"; continue }
    if ($row.sha256) {
      $cur = Sha256 $arc
      if ($cur -and ($cur -ne $row.sha256)) { Warn "checksum MISMATCH for $($row.archive); skipping"; continue }
    }
    if ($InPlace) { $dest = Split-Path -Parent $row.source }
    else { $dest = Join-Path (Join-Path $snap 'restored') (Sanitize $row.source) }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    try { Expand-Archive -Path $arc -DestinationPath $dest -Force; Good "restored $($row.source) -> $dest" }
    catch { Warn "restore $($row.source): $($_.Exception.Message)" }
  }
  if ((Have 'docker') -and (Test-Path (Join-Path $snap 'docker.csv'))) {
    foreach ($row in (Import-Csv (Join-Path $snap 'docker.csv'))) {
      if (-not $row.image_archive) { continue }
      $arc = Join-Path $snap $row.image_archive
      if (-not (Test-Path $arc)) { continue }
      & docker load -i $arc *> $null
      if ($LASTEXITCODE -eq 0) { Good "loaded image for container $($row.name)" } else { Warn "docker load $($row.name) failed" }
    }
  }
  Good "restore finished"
  if (-not $InPlace) { Info "files extracted into $snap\restored for review; re-run with -InPlace -Force to overwrite live paths" }
  exit 0
}

# ============================================================== SNAPSHOT ====
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$snap = Join-Path $Out "$Host_-$stamp"
$filesDir = Join-Path $snap 'files'
$dockerDir = Join-Path $snap 'docker'
New-Item -ItemType Directory -Force -Path $filesDir | Out-Null

function Is-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
$notes = @()
if (-not (Is-Elevated)) { Warn "not elevated: some protected files will be skipped"; $notes += 'not run as Administrator; some protected files were unreadable and skipped' }

$targets = if ($Paths) { $Paths.Split(',') | ForEach-Object { $_.Trim() } } else { Default-Paths }
if ($Add) { $targets += ($Add.Split(',') | ForEach-Object { $_.Trim() }) }

$fileRows = New-Object System.Collections.Generic.List[object]
Info "snapshotting candidate folders into $snap"
foreach ($t in $targets) {
  if (-not $t) { continue }
  if (-not (Test-Path $t)) { Info "skip $t (not present)"; continue }
  $arcName = (Sanitize $t) + '.zip'
  $arcPath = Join-Path $filesDir $arcName
  try {
    Compress-Archive -Path $t -DestinationPath $arcPath -Force -ErrorAction Stop
    $sha = Sha256 $arcPath
    Good "archived $t"
  } catch { $sha = ''; Warn ("archive {0}: {1}" -f $t, $_.Exception.Message) }
  $fileRows.Add([pscustomobject]@{ source=$t; archive="files/$arcName"; sha256=$sha })
}
$fileRows | Export-Csv -Path (Join-Path $snap 'files.csv') -NoTypeInformation -Encoding UTF8

# --- Docker ---
$dockerRows = New-Object System.Collections.Generic.List[object]
if (-not $NoDocker -and (Have 'docker')) {
  New-Item -ItemType Directory -Force -Path $dockerDir | Out-Null
  $ps = & docker ps --format '{{.ID}}`t{{.Names}}`t{{.Image}}' 2>$null
  foreach ($line in $ps) {
    if (-not $line) { continue }
    $cols = $line -split "`t"
    if ($cols.Count -lt 2) { continue }
    $id = $cols[0]; $name = $cols[1]
    Info "backing up container $name ($id)"
    & docker inspect $id > (Join-Path $dockerDir "$name.inspect.json") 2>$null
    $tag = "wrccdc-snap/" + ((Sanitize $name).ToLower()) + ":$stamp"
    & docker commit $id $tag *> $null
    if ($LASTEXITCODE -eq 0) {
      $tar = Join-Path $dockerDir "$name.image.tar"
      & docker save $tag -o $tar *> $null
      if (Test-Path $tar) {
        # gzip the tar.
        try {
          $in = [System.IO.File]::OpenRead($tar)
          $outF = [System.IO.File]::Create("$tar.gz")
          $gz = New-Object System.IO.Compression.GzipStream($outF, [System.IO.Compression.CompressionMode]::Compress)
          $in.CopyTo($gz); $gz.Close(); $outF.Close(); $in.Close(); Remove-Item $tar -Force
          $dockerRows.Add([pscustomobject]@{ name=$name; image_archive="docker/$name.image.tar.gz" })
        } catch { $dockerRows.Add([pscustomobject]@{ name=$name; image_archive="docker/$name.image.tar" }) }
      }
      & docker image rm $tag *> $null
    } else { Warn "docker commit $name failed" }
    # Named volumes via throwaway alpine container.
    $fmt = '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}{{println}}{{end}}'
    $mounts = & docker inspect --format $fmt $id 2>$null
    foreach ($ml in $mounts) {
      $mp = $ml -split '\|'
      if ($mp.Count -lt 2 -or $mp[0] -ne 'volume' -or -not $mp[1]) { continue }
      $vname = $mp[1]
      $abs = (Resolve-Path $dockerDir).Path
      & docker run --rm -v "${vname}:/v:ro" -v "${abs}:/backup" alpine sh -c "tar czf /backup/$name.vol.$(Sanitize $vname).tar.gz -C /v ." *> $null
      if ($LASTEXITCODE -eq 0) { Good "archived volume $vname (container-tar)" } else { Warn "could not back up volume $vname" }
    }
  }
  $dockerRows | Export-Csv -Path (Join-Path $snap 'docker.csv') -NoTypeInformation -Encoding UTF8
} elseif (-not $NoDocker) {
  $notes += 'docker not installed; container backup skipped'
}

# --- MANIFEST.json (Go-shaped) ---
$manifest = [ordered]@{
  host = $Host_; os = 'windows'; created = (Get-Date).ToString('o')
  files = @($fileRows | ForEach-Object { [ordered]@{ source=$_.source; archive=$_.archive; sha256=$_.sha256 } })
  notes = $notes
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $snap 'MANIFEST.json') -Encoding UTF8
Good "snapshot complete: $snap"

# --- Mirror ---
if ($Mirror) {
  $dst = Join-Path $Mirror (Split-Path -Leaf $snap)
  Info "mirroring snapshot to $dst"
  try { Copy-Item -Path $snap -Destination $dst -Recurse -Force; Good "mirror complete: $dst" }
  catch { Warn "mirror failed: $($_.Exception.Message)" }
}
