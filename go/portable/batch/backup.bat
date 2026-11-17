@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  backup.bat - Windows pseudo-snapshot & restore (portable fallback for the
rem  Go `backup`). Archives the folders red teams wipe or deface (IIS web root,
rem  DNS zone files, OpenSSH config, XAMPP/WAMP/Apache web roots) and running
rem  Docker containers, with sha256 checksums and a CSV manifest so restoration
rem  is verifiable. Standalone paste-able cmd.exe rewrite of cmd/backup (Windows).
rem
rem  Requires tar.exe (Win10 1803+/Server 2019+) and certutil (always present).
rem  Docker image archives are stored UNCOMPRESSED (.tar) in the batch version.
rem
rem    backup.bat /mirror E:\backups
rem    backup.bat /nodocker /paths "C:\inetpub\wwwroot,C:\Windows\System32\dns"
rem    backup.bat /restore C:\ProgramData\wrccdc\snapshots\HOST-20261111_120000
rem    backup.bat /restore <snapdir> /inplace /force
rem ============================================================================

set "OUTBASE="
set "PATHS="
set "ADD="
set "NODOCKER=0"
set "MIRROR="
set "RESTORE="
set "INPLACE=0"
set "FORCE=0"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="/out"     ( set "OUTBASE=%~2" & shift & shift & goto parse )
if /i "%~1"=="/paths"   ( set "PATHS=%~2" & shift & shift & goto parse )
if /i "%~1"=="/add"     ( set "ADD=%~2" & shift & shift & goto parse )
if /i "%~1"=="/nodocker"( set "NODOCKER=1" & shift & goto parse )
if /i "%~1"=="/mirror"  ( set "MIRROR=%~2" & shift & shift & goto parse )
if /i "%~1"=="/restore" ( set "RESTORE=%~2" & shift & shift & goto parse )
if /i "%~1"=="/inplace" ( set "INPLACE=1" & shift & goto parse )
if /i "%~1"=="/force"   ( set "FORCE=1" & shift & goto parse )
echo unknown flag: %~1 & exit /b 2
:parsed

where tar >nul 2>&1 || ( call :log "-" "tar.exe not found (needs Win10 1803+/Server 2019+)" & exit /b 1 )

set "HOSTN=%COMPUTERNAME%"
set "SECRETDIR=%ProgramData%\wrccdc"
if "%ProgramData%"=="" set "SECRETDIR=%SystemDrive%\wrccdc"
if not defined OUTBASE set "OUTBASE=%SECRETDIR%\snapshots"

if defined RESTORE goto do_restore

rem ============================================================ SNAPSHOT =====
for /f "tokens=1-6 delims=/:. " %%a in ("%DATE% %TIME%") do set "STAMP=%%c%%a%%b_%%d%%e%%f"
set "STAMP=%STAMP: =0%"
set "SNAP=%OUTBASE%\%HOSTN%-%STAMP%"
set "FILESDIR=%SNAP%\files"
set "DOCKERDIR=%SNAP%\docker"
md "%FILESDIR%" >nul 2>&1
set "CSV=%SNAP%\files.csv"
break> "%CSV%"

net session >nul 2>&1 || call :log "!" "not elevated: some protected files will be skipped"

if defined PATHS ( set "TARGETS=%PATHS%" ) else ( call :defaultpaths )
if defined ADD set "TARGETS=!TARGETS!,%ADD%"

call :log "*" "snapshotting candidate folders into %SNAP%"
for %%T in ("!TARGETS:,=" "!") do call :archive %%~T

rem --- Docker ---
if "%NODOCKER%"=="0" (
  where docker >nul 2>&1 && ( md "%DOCKERDIR%" >nul 2>&1 & call :docker_backup ) || call :log "*" "docker not installed; container backup skipped"
)

rem --- MANIFEST.txt (human-readable; files.csv drives restore) ---
> "%SNAP%\MANIFEST.txt" echo host=%HOSTN%
>>"%SNAP%\MANIFEST.txt" echo os=windows
>>"%SNAP%\MANIFEST.txt" echo created=%DATE% %TIME%
>>"%SNAP%\MANIFEST.txt" echo (see files.csv for source,archive,sha256)
icacls "%SNAP%" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F /t >nul 2>&1
call :log "+" "snapshot complete: %SNAP%"

if defined MIRROR (
  set "DST=%MIRROR%\%HOSTN%-%STAMP%"
  call :log "*" "mirroring snapshot to !DST!"
  robocopy "%SNAP%" "!DST!" /E /NFL /NDL /NJH /NJS /NP >nul 2>&1
  if errorlevel 8 ( call :log "!" "mirror failed" ) else ( call :log "+" "mirror complete: !DST!" )
)
exit /b 0

:archive
set "T=%~1"
if "%T%"=="" goto :eof
if not exist "%T%" ( call :log "*" "skip %T% (not present)" & goto :eof )
call :sanitize "%T%"
set "ARC=%FILESDIR%\!SAN!.tar.gz"
for %%p in ("%T%") do set "PARENT=%%~dpp"
for %%p in ("%T%") do set "BASE=%%~nxp"
tar -czf "%ARC%" -C "!PARENT!." "!BASE!" >nul 2>&1
if errorlevel 1 ( call :log "!" "archive %T% had errors" & set "SHA=" ) else ( call :sha256 "%ARC%" & call :log "+" "archived %T%" )
>>"%CSV%" echo %T%,files/!SAN!.tar.gz,!SHA!
goto :eof

:docker_backup
for /f "usebackq tokens=1,2" %%i in (`docker ps --format "{{.ID}} {{.Names}}" 2^>nul`) do (
  set "CID=%%i"
  set "CNAME=%%j"
  call :log "*" "backing up container !CNAME! (!CID!)"
  docker inspect !CID! > "%DOCKERDIR%\!CNAME!.inspect.json" 2>nul
  call :sanitize "!CNAME!"
  set "TAG=wrccdc-snap/!SAN!:%STAMP%"
  docker commit !CID! "!TAG!" >nul 2>&1 && (
    docker save "!TAG!" -o "%DOCKERDIR%\!CNAME!.image.tar" >nul 2>&1
    docker image rm "!TAG!" >nul 2>&1
    call :log "+" "saved image for !CNAME! (uncompressed .tar)"
  ) || call :log "!" "docker commit !CNAME! failed"
)
goto :eof

rem ============================================================ RESTORE ======
:do_restore
set "SNAP=%RESTORE%"
if not exist "%SNAP%\files.csv" ( call :log "-" "no files.csv in %SNAP% (was this made by backup.bat?)" & exit /b 1 )
if "%INPLACE%"=="1" if "%FORCE%"=="0" ( call :log "-" "in-place restore overwrites live files; add /inplace /force" & exit /b 1 )
call :log "*" "restoring snapshot from %SNAP%"
for /f "usebackq tokens=1,2,3 delims=," %%a in ("%SNAP%\files.csv") do (
  set "SRC=%%a"
  set "ARCREL=%%b"
  set "WANTSHA=%%c"
  set "ARC=%SNAP%\!ARCREL:/=\!"
  if not exist "!ARC!" ( call :log "!" "missing archive !ARCREL!; skipping" ) else ( call :restore_one )
)
if "%NODOCKER%"=="0" if exist "%SNAP%\docker" where docker >nul 2>&1 && (
  for %%f in ("%SNAP%\docker\*.image.tar") do (
    docker load -i "%%f" >nul 2>&1 && call :log "+" "loaded image %%~nxf" || call :log "!" "docker load %%~nxf failed"
  )
)
call :log "+" "restore finished"
if "%INPLACE%"=="0" call :log "*" "files extracted into %SNAP%\restored for review; re-run with /inplace /force to overwrite live paths"
exit /b 0

:restore_one
if defined WANTSHA (
  call :sha256 "!ARC!"
  if /i not "!SHA!"=="!WANTSHA!" ( call :log "!" "checksum MISMATCH for !ARCREL!; skipping" & goto :eof )
)
if "%INPLACE%"=="1" (
  for %%p in ("!SRC!") do set "DEST=%%~dpp"
) else (
  call :sanitize "!SRC!"
  set "DEST=%SNAP%\restored\!SAN!"
  md "!DEST!" >nul 2>&1
)
tar -xf "!ARC!" -C "!DEST!." >nul 2>&1 && call :log "+" "restored !SRC! -> !DEST!" || call :log "!" "restore !SRC! failed"
goto :eof

rem --------------------------------------------------------------- helpers ---
:defaultpaths
set "SR=%SystemRoot%"
if "%SR%"=="" set "SR=C:\Windows"
set "SD=%SystemDrive%"
if "%SD%"=="" set "SD=C:"
set "PD=%ProgramData%"
if "%PD%"=="" set "PD=C:\ProgramData"
set "TARGETS=%SD%\inetpub\wwwroot,%SD%\inetpub,%SR%\System32\dns,%PD%\ssh,%SD%\xampp\htdocs,%SD%\wamp\www,%SD%\Apache24\htdocs"
goto :eof

:sanitize
set "SAN=%~1"
set "SAN=!SAN::=_!"
set "SAN=!SAN:\=_!"
set "SAN=!SAN:/=_!"
set "SAN=!SAN: =_!"
if "!SAN:~0,1!"=="_" set "SAN=!SAN:~1!"
if "!SAN!"=="" set "SAN=root"
goto :eof

:sha256
set "SHA="
for /f "skip=1 tokens=* delims=" %%h in ('certutil -hashfile "%~1" SHA256 2^>nul') do if not defined SHA set "SHA=%%h"
set "SHA=!SHA: =!"
goto :eof

:log
echo [%TIME:~0,8%] [%~1] %~2 1>&2
goto :eof
