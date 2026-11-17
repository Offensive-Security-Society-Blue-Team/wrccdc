@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  enum.bat - Windows host enumeration (portable fallback for the Go `enum`).
rem  Collects systeminfo, IP config, listening ports and owning PIDs, routes,
rem  ARP, processes, local users/admins, sessions, scheduled tasks, shares,
rem  services, installed applications and firewall posture into one report.
rem  Standalone paste-able cmd.exe rewrite of cmd/enum (Windows behavior).
rem
rem    enum.bat                 writes %TEMP%\<host>-enum.txt
rem    enum.bat C:\enum.txt     writes to the given path
rem
rem  A full run can take ~30-60 seconds (systeminfo + several queries).
rem ============================================================================

set "OUT=%~1"
if not defined OUT set "OUT=%TEMP%\%COMPUTERNAME%-enum.txt"

call :log "*" "host=%COMPUTERNAME% os=windows"
net session >nul 2>&1 || call :log "!" "not running as Administrator: some sections will be incomplete"

> "%OUT%" echo ==================================================
>>"%OUT%" echo Host
>>"%OUT%" echo --------------------------------------------------
>>"%OUT%" echo hostname: %COMPUTERNAME%
>>"%OUT%" echo os: windows
>>"%OUT%" echo collected: %DATE% %TIME%
>>"%OUT%" echo.

call :sec "OS version"                     ver
call :sec "System info"                    systeminfo
call :sec "IP configuration"               ipconfig /all
call :sec "Listening ports and owning PIDs"  netstat -ano
call :sec "Routing table"                  route print
call :sec "ARP cache"                      arp -a
call :sec "Running processes"              tasklist /v
call :sec "Local users"                    net user
call :sec "Administrators group"           net localgroup administrators
call :sec "Active sessions"                query session
call :sec "Scheduled tasks"                schtasks /query /fo LIST /v
call :sec "Shares"                         net share
call :sec "Services (sc query)"            sc query state^= all
call :sec "Firewall profiles"              netsh advfirewall show allprofiles

rem Installed applications from the uninstall registry keys.
>>"%OUT%" echo ==================================================
>>"%OUT%" echo Installed applications
>>"%OUT%" echo --------------------------------------------------
for %%K in (
  "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
) do (
  for /f "tokens=*" %%S in ('reg query %%K 2^>nul') do (
    for /f "tokens=2,*" %%a in ('reg query "%%S" /v DisplayName 2^>nul ^| findstr /i "DisplayName"') do (
      >>"%OUT%" echo %%b
    )
  )
)
>>"%OUT%" echo.

call :log "+" "enumeration written to %OUT%"
icacls "%OUT%" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F >nul 2>&1
exit /b 0

rem ------------------------------------------------------------------- :sec
rem %1 = title (quoted), remaining args = command line to run.
:sec
set "TITLE=%~1"
shift
set "CMD=%1"
:secargs
shift
if not "%~1"=="" ( set "CMD=!CMD! %1" & goto secargs )
>>"%OUT%" echo ==================================================
>>"%OUT%" echo !TITLE!
>>"%OUT%" echo --------------------------------------------------
!CMD! >> "%OUT%" 2>&1
>>"%OUT%" echo.
goto :eof

:log
echo [%TIME:~0,8%] [%~1] %~2 1>&2
goto :eof
