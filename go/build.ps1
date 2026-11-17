# Build every tool for Linux and Windows (amd64) into bin\.
# Pure Go, no cgo, so this cross-compiles from a Windows host too.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$tools   = @('enum','rotatepw','revoke','backup','defaultcreds')
$ldflags = '-s -w'

function Build([string]$goos, [string]$goarch, [string]$ext) {
    $outdir = "bin/$goos-$goarch"
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    foreach ($t in $tools) {
        Write-Host "  $goos/$goarch: $t$ext"
        $env:CGO_ENABLED = '0'; $env:GOOS = $goos; $env:GOARCH = $goarch
        go build -trimpath -ldflags $ldflags -o "$outdir/$t$ext" "./cmd/$t"
        if ($LASTEXITCODE -ne 0) { throw "build failed for $t ($goos/$goarch)" }
    }
}

Write-Host 'Building Linux (amd64)...'
Build 'linux' 'amd64' ''
Write-Host 'Building Windows (amd64)...'
Build 'windows' 'amd64' '.exe'
Remove-Item Env:CGO_ENABLED,Env:GOOS,Env:GOARCH -ErrorAction SilentlyContinue
Write-Host 'Done. Binaries are in bin\.'
