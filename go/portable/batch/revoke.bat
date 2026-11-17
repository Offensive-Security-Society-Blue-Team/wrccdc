@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  revoke.bat - Windows intruder eviction (portable fallback for the Go
rem  `revoke`). Three stages: log off every interactive/RDP session except your
rem  own and drop inbound SMB sessions; rotate local passwords for human
rem  accounts; then log sessions off again. Standalone paste-able cmd.exe rewrite
rem  of cmd/revoke (Windows LOCAL behavior). Domain rotation is NOT performed by
rem  the batch version - use revoke.ps1 or the Go binary on a DC.
rem
rem  Run elevated. Same password limitations as rotatepw.bat (alphanumeric,
rem  %%RANDOM%%; prefer Go/PowerShell/bash when available).
rem
rem    revoke.bat                 full sequence, preserves your session
rem    revoke.bat /norotate       only revoke sessions
rem    revoke.bat /noroot /length 28 /deny svc1,svc2
rem ============================================================================

set "LENGTH=24"
set "INCLUDE_ROOT=1"
set "INCLUDE_SELF=0"
set "NOROTATE=0"
set "DENY_EXTRA=,"
set "OUT="

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="/norotate"    ( set "NOROTATE=1" & shift & goto parse )
if /i "%~1"=="/noroot"      ( set "INCLUDE_ROOT=0" & shift & goto parse )
if /i "%~1"=="/includeself" ( set "INCLUDE_SELF=1" & shift & goto parse )
if /i "%~1"=="/length"      ( set "LENGTH=%~2" & shift & shift & goto parse )
if /i "%~1"=="/deny"        ( set "DENY_EXTRA=,%~2," & shift & shift & goto parse )
if /i "%~1"=="/out"         ( set "OUT=%~2" & shift & shift & goto parse )
echo unknown flag: %~1 & exit /b 2
:parsed

set "HOSTN=%COMPUTERNAME%"
set "SELF=%USERNAME%"
call :tolower SELF

if not defined OUT (
  set "SECRETDIR=%ProgramData%\wrccdc"
  if "%ProgramData%"=="" set "SECRETDIR=%SystemDrive%\wrccdc"
  set "OUT=!SECRETDIR!\%HOSTN%-revoke_passwords.txt"
) else (
  for %%d in ("%OUT%") do set "SECRETDIR=%%~dpd"
)
if not exist "%SECRETDIR%" md "%SECRETDIR%" >nul 2>&1

set "DENY=,root,daemon,bin,sys,sync,games,man,lp,mail,news,uucp,proxy,backup,list,irc,gnats,nobody,systemd-network,systemd-resolve,systemd-timesync,messagebus,syslog,_apt,tss,uuidd,tcpdump,landscape,pollinate,sshd,systemd-coredump,lxd,dnsmasq,ntp,chrony,mysql,postgres,redis,mongodb,mongod,nginx,www-data,apache,httpd,named,bind,git,gitea,forgejo,nobody4,ftp,vmail,dovecot,dovenull,postfix,clamav,amavis,haproxy,memcache,rabbitmq,elasticsearch,grafana,prometheus,docker,containerd,nixbld,snapd,krbtgt,guest,defaultaccount,wdagutilityaccount,sshd_server,healthmailbox,"

net session >nul 2>&1
if errorlevel 1 ( call :log "-" "must run as Administrator" & exit /b 1 )

call :log "*" "host=%HOSTN% os=windows - stage 1: revoking sessions"
call :revoke 1

if "%NOROTATE%"=="0" (
  call :rotate
) else (
  call :log "*" "stage 2 skipped (/norotate)"
)

call :revoke 3
echo.
echo Done. Verify no unexpected sessions remain and that the credential record is stored off-box.
exit /b 0

rem ------------------------------------------------------------------ :revoke
:revoke
call :log "*" "stage %~1: revoking sessions"
for /f "usebackq delims=" %%L in (`query session 2^>nul`) do (
  set "LINE=%%L"
  call :sessline
)
rem Drop inbound SMB sessions (file-share footholds).
net session /delete /y >nul 2>&1 && call :log "+" "closed inbound SMB sessions (net session)"
goto :eof

:sessline
set "RAW=!LINE!"
rem Skip header.
echo !RAW!| findstr /b /c:" SESSIONNAME" >nul && goto :eof
echo !RAW!| findstr /c:"SESSIONNAME  USERNAME" >nul && goto :eof
rem Current session is marked with a leading '>'.
set "CUR=0"
if "!RAW:~0,1!"==">" set "CUR=1"
rem Find the first all-numeric token = session ID.
set "SID="
set "ST="
for %%t in (!RAW!) do (
  echo %%t| findstr /r "^[0-9][0-9]*$" >nul && if not defined SID set "SID=%%t"
)
if not defined SID goto :eof
if "!SID!"=="0" goto :eof
if "!SID!"=="65536" goto :eof
if "!CUR!"=="1" ( call :log "+" "kept own session id=!SID!" & goto :eof )
logoff !SID! >nul 2>&1 && call :log "+" "logged off session id=!SID!" || call :log "!" "logoff !SID! failed"
goto :eof

rem ------------------------------------------------------------------ :rotate
:rotate
call :log "*" "stage 2: rotating passwords (local)"
set "TMPREC=%TEMP%\revoke_rec_%RANDOM%.txt"
set "TMPSKIP=%TEMP%\revoke_skip_%RANDOM%.txt"
break> "%TMPREC%"
break> "%TMPSKIP%"
for /f "tokens=2,3,4 delims=," %%a in ('wmic useraccount where "LocalAccount=true" get Disabled^,Name^,SID /format:csv 2^>nul ^| findstr "S-1-"') do (
  set "U_DIS=%%a"
  set "U_NAME=%%b"
  set "U_SID=%%c"
  call :consider
)
> "%OUT%" echo # WRCCDC password rotation record
>>"%OUT%" echo # host=%HOSTN% os=windows time=%DATE% %TIME%
>>"%OUT%" echo # KEEP THIS FILE SECRET. Record it off-box, then delete.
>>"%OUT%" echo scope,username,password,status
type "%TMPREC%" >> "%OUT%" 2>nul
>>"%OUT%" echo.
>>"%OUT%" echo # skipped (left intentionally alone):
type "%TMPSKIP%" >> "%OUT%" 2>nul
icacls "%OUT%" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F >nul 2>&1
call :log "+" "credentials written to %OUT% (admins/SYSTEM only)"
del "%TMPREC%" "%TMPSKIP%" >nul 2>&1
goto :eof

:consider
for /f "delims=" %%x in ("!U_SID!") do set "U_SID=%%x"
set "NAME=%U_NAME%"
set "LNAME=%U_NAME%"
call :tolower LNAME
set "REASON="
echo %U_SID%| findstr /r "\-501$ \-503$ \-504$" >nul && set "REASON=built-in system account"
if not defined REASON echo %U_SID%| findstr /r "\-500$" >nul && ( if "%INCLUDE_ROOT%"=="0" set "REASON=built-in Administrator" )
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
  >>"%TMPSKIP%" echo # - !NAME! ^(!REASON!^)
  goto :eof
)
call :genpw %LENGTH%
net user "!NAME!" "!PW!" >nul 2>&1
if errorlevel 1 (
  call :log "-" "local !NAME! error: net user failed"
  >>"%TMPREC%" echo local,!NAME!,,error: net user failed
) else (
  call :log "+" "local !NAME! changed"
  >>"%TMPREC%" echo local,!NAME!,!PW!,changed
)
goto :eof

rem ------------------------------------------------------------------ :genpw
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
for /l %%i in (!LAST!,-1,1) do ( set /a JJ=!RANDOM! %% (%%i+1) & call :swap %%i !JJ! )
set "OUTPW="
for /l %%i in (0,1,!LAST!) do set "OUTPW=!OUTPW!!CHARS[%%i]!"
endlocal & set "PW=%OUTPW%"
goto :eof
:swap
set "SA=!CHARS[%1]!"
set "SB=!CHARS[%2]!"
set "CHARS[%1]=!SB!"
set "CHARS[%2]=!SA!"
goto :eof
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

:log
echo [%TIME:~0,8%] [%~1] %~2 1>&2
goto :eof

:tolower
setlocal EnableDelayedExpansion
set "s=!%~1!"
for %%A in ("A=a" "B=b" "C=c" "D=d" "E=e" "F=f" "G=g" "H=h" "I=i" "J=j" "K=k" "L=l" "M=m" "N=n" "O=o" "P=p" "Q=q" "R=r" "S=s" "T=t" "U=u" "V=v" "W=w" "X=x" "Y=y" "Z=z") do set "s=!s:%%~A!"
endlocal & set "%~1=%s%"
goto :eof
