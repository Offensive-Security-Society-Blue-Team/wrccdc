@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  rotatepw.bat - Windows local password rotation (portable fallback for the
rem  Go `rotatepw`). Rotates enabled local users while leaving built-in,
rem  disabled and service/system accounts untouched, and records new credentials
rem  to a locked-down file. Standalone paste-able cmd.exe rewrite of
rem  cmd/rotatepw (Windows LOCAL behavior). Domain (AD) rotation is NOT performed
rem  by the batch version - use rotatepw.ps1 or the Go binary on a DC.
rem
rem  Run from an elevated (Administrator) cmd. Requires wmic + net (present on
rem  Server 2016-2022 and Win10/11 pre-24H2).
rem
rem  NOTES / LIMITATIONS of the batch version:
rem   * Passwords are ALPHANUMERIC only. cmd.exe cannot safely carry the symbol
rem     set (! ^ %% & | < >) through variables or `net user`, so symbols are
rem     omitted and the default length is raised to 24 to compensate.
rem   * Passwords use %%RANDOM%% which is NOT cryptographically secure. Prefer the
rem     Go, PowerShell or bash version whenever you can run them.
rem
rem    rotatepw.bat                 rotate enabled local users
rem    rotatepw.bat /dryrun         preview only, change nothing
rem    rotatepw.bat /length 28
rem    rotatepw.bat /noroot         do NOT rotate the built-in Administrator
rem    rotatepw.bat /deny svc1,svc2
rem ============================================================================

set "LENGTH=24"
set "INCLUDE_ROOT=1"
set "INCLUDE_SELF=0"
set "DRYRUN=0"
set "DENY_EXTRA=,"
set "OUT="

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="/length"      ( set "LENGTH=%~2" & shift & shift & goto parse )
if /i "%~1"=="/noroot"      ( set "INCLUDE_ROOT=0" & shift & goto parse )
if /i "%~1"=="/includeself" ( set "INCLUDE_SELF=1" & shift & goto parse )
if /i "%~1"=="/dryrun"      ( set "DRYRUN=1" & shift & goto parse )
if /i "%~1"=="/out"         ( set "OUT=%~2" & shift & shift & goto parse )
if /i "%~1"=="/deny"        ( set "DENY_EXTRA=,%~2," & shift & shift & goto parse )
echo unknown flag: %~1 & exit /b 2
:parsed

set "HOSTN=%COMPUTERNAME%"
set "SELF=%USERNAME%"
call :tolower SELF

if not defined OUT (
  set "SECRETDIR=%ProgramData%\wrccdc"
  if "%ProgramData%"=="" set "SECRETDIR=%SystemDrive%\wrccdc"
  set "OUT=!SECRETDIR!\%HOSTN%-new_passwords.txt"
) else (
  for %%d in ("%OUT%") do set "SECRETDIR=%%~dpd"
)
if not exist "%SECRETDIR%" md "%SECRETDIR%" >nul 2>&1

rem Baseline service/system deny list (lowercased), comma-delimited.
set "DENY=,root,daemon,bin,sys,sync,games,man,lp,mail,news,uucp,proxy,backup,list,irc,gnats,nobody,systemd-network,systemd-resolve,systemd-timesync,messagebus,syslog,_apt,tss,uuidd,tcpdump,landscape,pollinate,sshd,systemd-coredump,lxd,dnsmasq,ntp,chrony,mysql,postgres,redis,mongodb,mongod,nginx,www-data,apache,httpd,named,bind,git,gitea,forgejo,nobody4,ftp,vmail,dovecot,dovenull,postfix,clamav,amavis,haproxy,memcache,rabbitmq,elasticsearch,grafana,prometheus,docker,containerd,nixbld,snapd,krbtgt,guest,defaultaccount,wdagutilityaccount,sshd_server,healthmailbox,"

call :log "*" "host=%HOSTN% os=windows (dry-run=%DRYRUN%)"

net session >nul 2>&1
if errorlevel 1 if "%DRYRUN%"=="0" (
  call :log "-" "must run elevated (Administrator) to change passwords (use /dryrun to preview)"
  exit /b 1
)

set "TMPREC=%TEMP%\rotatepw_rec_%RANDOM%.txt"
set "TMPSKIP=%TEMP%\rotatepw_skip_%RANDOM%.txt"
break> "%TMPREC%"
break> "%TMPSKIP%"
set /a CHANGED=0, SKIPPED=0, ERRORS=0

rem Enumerate local accounts: Disabled, Name, SID. Only data rows contain S-1-.
for /f "tokens=2,3,4 delims=," %%a in ('wmic useraccount where "LocalAccount=true" get Disabled^,Name^,SID /format:csv 2^>nul ^| findstr "S-1-"') do (
  set "U_DIS=%%a"
  set "U_NAME=%%b"
  set "U_SID=%%c"
  call :consider
)

if "%DRYRUN%"=="0" (
  > "%OUT%" echo # WRCCDC password rotation record
  >>"%OUT%" echo # host=%HOSTN% os=windows time=%DATE% %TIME%
  >>"%OUT%" echo # KEEP THIS FILE SECRET. Record it off-box, then delete.
  >>"%OUT%" echo scope,username,password,status
  type "%TMPREC%" >> "%OUT%" 2>nul
  >>"%OUT%" echo.
  >>"%OUT%" echo # skipped (left intentionally alone):
  type "%TMPSKIP%" >> "%OUT%" 2>nul
  icacls "%OUT%" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F >nul 2>&1
  call :log "+" "credentials written to %OUT% (admins/SYSTEM only) - record off-box then delete"
)
del "%TMPREC%" "%TMPSKIP%" >nul 2>&1

echo.
echo Summary: %CHANGED% accounts changed, %SKIPPED% skipped, %ERRORS% errors
if %ERRORS% gtr 0 exit /b 1
exit /b 0

rem ---------------------------------------------------------------- :consider
:consider
rem Strip any trailing CR the wmic|for pipeline leaves on the last field (SID).
for /f "delims=" %%x in ("!U_SID!") do set "U_SID=%%x"
set "NAME=%U_NAME%"
set "LNAME=%U_NAME%"
call :tolower LNAME
set "REASON="

echo %U_SID%| findstr /r "\-501$ \-503$ \-504$" >nul && set "REASON=built-in system account"
if not defined REASON (
  echo %U_SID%| findstr /r "\-500$" >nul && (
    if "%INCLUDE_ROOT%"=="0" set "REASON=built-in Administrator (default rotates it)"
  )
)
if not defined REASON if /i "%U_DIS%"=="TRUE" set "REASON=disabled account"
if not defined REASON if "%INCLUDE_SELF%"=="0" if "!LNAME!"=="%SELF%" set "REASON=current user"
if not defined REASON echo !DENY!| findstr /i /c:",!LNAME!," >nul && set "REASON=service/system account"
if not defined REASON echo !DENY_EXTRA!| findstr /i /c:",!LNAME!," >nul && set "REASON=service/system account (deny)"
if not defined REASON (
  if "!LNAME:~0,1!"=="_"      set "REASON=service/system account"
  if "!LNAME:~0,4!"=="svc-"   set "REASON=service/system account"
  if "!LNAME:~0,4!"=="svc_"   set "REASON=service/system account"
  if "!LNAME:~0,6!"=="nixbld" set "REASON=service/system account"
)

if defined REASON (
  call :log "*" "skip: !NAME! (!REASON!)"
  >>"%TMPSKIP%" echo # - !NAME! ^(!REASON!^)
  set /a SKIPPED+=1
  goto :eof
)

call :genpw %LENGTH%
if "%DRYRUN%"=="1" (
  call :log "*" "local !NAME! would change"
  >>"%TMPREC%" echo local,!NAME!,!PW!,dry-run
  set /a CHANGED+=1
  goto :eof
)
net user "!NAME!" "!PW!" >nul 2>&1
if errorlevel 1 (
  call :log "-" "local !NAME! error: net user failed"
  >>"%TMPREC%" echo local,!NAME!,,error: net user failed
  set /a ERRORS+=1
) else (
  call :log "+" "local !NAME! changed"
  >>"%TMPREC%" echo local,!NAME!,!PW!,changed
  set /a CHANGED+=1
)
goto :eof

rem ------------------------------------------------------------------ :genpw
rem %1 = length. Sets PW (alphanumeric, ambiguity-free set). Uses %RANDOM%.
:genpw
setlocal EnableDelayedExpansion
set "L=abcdefghijkmnopqrstuvwxyz"
set "U=ABCDEFGHJKLMNPQRSTUVWXYZ"
set "D=23456789"
set "POOL=!L!!U!!D!"
set /a GLEN=%1
if !GLEN! lss 8 set /a GLEN=8
call :pick "!L!" & set "CHARS[0]=!RCH!"
call :pick "!U!" & set "CHARS[1]=!RCH!"
call :pick "!D!" & set "CHARS[2]=!RCH!"
set /a IDX=3
:genfill
if !IDX! geq !GLEN! goto genshuf
call :pick "!POOL!"
set "CHARS[!IDX!]=!RCH!"
set /a IDX+=1
goto genfill
:genshuf
set /a LAST=!GLEN!-1
for /l %%i in (!LAST!,-1,1) do (
  set /a JJ=!RANDOM! %% (%%i+1)
  call :swap %%i !JJ!
)
set "OUTPW="
for /l %%i in (0,1,!LAST!) do set "OUTPW=!OUTPW!!CHARS[%%i]!"
endlocal & set "PW=%OUTPW%"
goto :eof

rem Swap CHARS[%1] and CHARS[%2] (runs in genpw's delayed-expansion scope).
:swap
set "SA=!CHARS[%1]!"
set "SB=!CHARS[%2]!"
set "CHARS[%1]=!SB!"
set "CHARS[%2]=!SA!"
goto :eof

rem Pick one random char from %~1 into RCH.
:pick
setlocal EnableDelayedExpansion
set "SET=%~1"
set "SLEN=0"
:picklen
if not "!SET:~%SLEN%,1!"=="" ( set /a SLEN+=1 & goto picklen )
set /a PI=!RANDOM! %% !SLEN!
set "RC=!SET:~%PI%,1!"
endlocal & set "RCH=%RC%"
goto :eof

rem ------------------------------------------------------------------- :log
:log
echo [%TIME:~0,8%] [%~1] %~2 1>&2
goto :eof

rem ---------------------------------------------------------------- :tolower
:tolower
setlocal EnableDelayedExpansion
set "s=!%~1!"
for %%A in ("A=a" "B=b" "C=c" "D=d" "E=e" "F=f" "G=g" "H=h" "I=i" "J=j" "K=k" "L=l" "M=m" "N=n" "O=o" "P=p" "Q=q" "R=r" "S=s" "T=t" "U=u" "V=v" "W=w" "X=x" "Y=y" "Z=z") do set "s=!s:%%~A!"
endlocal & set "%~1=%s%"
goto :eof
