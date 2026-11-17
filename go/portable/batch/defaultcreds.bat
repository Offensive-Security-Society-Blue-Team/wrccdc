@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================================
rem  defaultcreds.bat - rotate stock service passwords (portable fallback for the
rem  Go `defaultcreds`, Windows behavior). Rotates default/known credentials for
rem  MySQL/MariaDB, Gitea and WordPress. Each service is best-effort: a missing
rem  tool/config is reported, not fatal. Standalone paste-able cmd.exe rewrite.
rem
rem  LIMITATIONS of the batch version:
rem   * Passwords are ALPHANUMERIC only (cmd.exe cannot safely carry symbols) and
rem     use %%RANDOM%% (not crypto). Prefer Go/PowerShell/bash when available.
rem   * WordPress DB fallback parses single-quoted wp-config.php defines only.
rem
rem    defaultcreds.bat /dryrun
rem    defaultcreds.bat /giteaadmin giteaadmin
rem    defaultcreds.bat /services mysql /mysqlall /mysqlpass oldRootPw
rem ============================================================================

set "SERVICES=mysql,wordpress,gitea"
set "OUT="
set "LENGTH=24"
set "DRYRUN=0"
set "MYSQLBIN="
set "MYUSER=root"
set "MYPASS="
set "MYHOST=127.0.0.1"
set "MYSQLALL=0"
set "WPPATH="
set "WPADMIN=admin"
set "GITEABIN="
set "GITEACONF="
set "GITEAADMIN="

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="/services"   ( set "SERVICES=%~2" & shift & shift & goto parse )
if /i "%~1"=="/out"        ( set "OUT=%~2" & shift & shift & goto parse )
if /i "%~1"=="/length"     ( set "LENGTH=%~2" & shift & shift & goto parse )
if /i "%~1"=="/dryrun"     ( set "DRYRUN=1" & shift & goto parse )
if /i "%~1"=="/mysqlbin"   ( set "MYSQLBIN=%~2" & shift & shift & goto parse )
if /i "%~1"=="/mysqluser"  ( set "MYUSER=%~2" & shift & shift & goto parse )
if /i "%~1"=="/mysqlpass"  ( set "MYPASS=%~2" & shift & shift & goto parse )
if /i "%~1"=="/mysqlhost"  ( set "MYHOST=%~2" & shift & shift & goto parse )
if /i "%~1"=="/mysqlall"   ( set "MYSQLALL=1" & shift & goto parse )
if /i "%~1"=="/wppath"     ( set "WPPATH=%~2" & shift & shift & goto parse )
if /i "%~1"=="/wpadmin"    ( set "WPADMIN=%~2" & shift & shift & goto parse )
if /i "%~1"=="/giteabin"   ( set "GITEABIN=%~2" & shift & shift & goto parse )
if /i "%~1"=="/giteaconfig"( set "GITEACONF=%~2" & shift & shift & goto parse )
if /i "%~1"=="/giteaadmin" ( set "GITEAADMIN=%~2" & shift & shift & goto parse )
echo unknown flag: %~1 & exit /b 2
:parsed

set "HOSTN=%COMPUTERNAME%"
set "SECRETDIR=%ProgramData%\wrccdc"
if "%ProgramData%"=="" set "SECRETDIR=%SystemDrive%\wrccdc"
if not defined OUT set "OUT=%SECRETDIR%\%HOSTN%-default_creds.txt"
if not exist "%SECRETDIR%" md "%SECRETDIR%" >nul 2>&1

set "TMPREC=%TEMP%\dc_rec_%RANDOM%.txt"
break> "%TMPREC%"
set "WANT=,%SERVICES%,"
call :tolowervar WANT

call :log "*" "host=%HOSTN% os=windows - rotating default service credentials (dry-run=%DRYRUN%)"

echo !WANT!| findstr /c:",mysql," >nul && call :do_mysql
echo !WANT!| findstr /c:",mariadb," >nul && call :do_mysql
echo !WANT!| findstr /c:",wordpress," >nul && call :do_wordpress
echo !WANT!| findstr /c:",wp," >nul && call :do_wordpress
echo !WANT!| findstr /c:",gitea," >nul && call :do_gitea
echo !WANT!| findstr /c:",forgejo," >nul && call :do_gitea

if "%DRYRUN%"=="0" (
  > "%OUT%" echo # WRCCDC password rotation record
  >>"%OUT%" echo # host=%HOSTN% os=windows time=%DATE% %TIME%
  >>"%OUT%" echo # KEEP THIS FILE SECRET. Record it off-box, then delete.
  >>"%OUT%" echo scope,username,password,status
  type "%TMPREC%" >> "%OUT%" 2>nul
  icacls "%OUT%" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F >nul 2>&1
  call :log "+" "credentials written to %OUT% (admins/SYSTEM only) - record off-box then delete"
)
del "%TMPREC%" >nul 2>&1
echo.
echo Done. Review statuses above; services not installed are reported, not errors.
exit /b 0

rem =============================================================== MySQL ======
:do_mysql
call :resolve_mysql
if not defined MBIN (
  call :log "-" "mysql - skipped: client not found (install or pass /mysqlbin)"
  >>"%TMPREC%" echo mysql,-,,skipped: mysql client not found
  goto :eof
)
if defined MYPASS set "MYSQL_PWD=%MYPASS%"
"%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "SELECT 1" >nul 2>&1
if errorlevel 1 (
  set "MYSQL_PWD="
  call :log "-" "mysql %MYUSER% - skipped: cannot authenticate"
  >>"%TMPREC%" echo mysql,%MYUSER%,,skipped: cannot authenticate
  goto :eof
)
if "%MYSQLALL%"=="1" (
  set "MLIST=%TEMP%\dc_myusers_%RANDOM%.txt"
  "%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "SELECT CONCAT(user,'@',host) FROM mysql.user" > "!MLIST!" 2>nul
  for /f "usebackq tokens=1,2 delims=@" %%u in ("!MLIST!") do (
    set "UU=%%u"
    call :tolowervar2 UU LUU
    set "SKIPU=0"
    for %%s in (mysql.sys mysql.session mysql.infoschema debian-sys-maint mariadb.sys) do if /i "%%u"=="%%s" set "SKIPU=1"
    if "!SKIPU!"=="0" call :rotate_mysql_user "%%u" "%%v"
  )
  del "!MLIST!" >nul 2>&1
) else (
  call :rotate_mysql_user "%MYUSER%" "localhost"
  call :rotate_mysql_user "%MYUSER%" "127.0.0.1"
  call :rotate_mysql_user "%MYUSER%" "%%"
)
set "MYSQL_PWD="
goto :eof

:rotate_mysql_user
set "RUSER=%~1"
set "RHOST=%~2"
set "TGT='%RUSER%'@'%RHOST%'"
rem Skip user@host that does not exist (default path probes 3 hosts).
if "%MYSQLALL%"=="0" (
  set "EXF=%TEMP%\dc_ex_%RANDOM%.txt"
  "%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "SELECT 1 FROM mysql.user WHERE user='%RUSER%' AND host='%RHOST%'" > "!EXF!" 2>nul
  for %%z in ("!EXF!") do if %%~zz EQU 0 ( del "!EXF!" >nul 2>&1 & goto :eof )
  del "!EXF!" >nul 2>&1
)
call :genpw %LENGTH%
if "%DRYRUN%"=="1" (
  call :log "+" "mysql !TGT! dry-run"
  >>"%TMPREC%" echo mysql,!TGT!,!PW!,dry-run
  goto :eof
)
"%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "ALTER USER !TGT! IDENTIFIED BY '!PW!'" >nul 2>&1
if errorlevel 1 "%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "SET PASSWORD FOR !TGT! = PASSWORD('!PW!')" >nul 2>&1
if errorlevel 1 (
  call :log "-" "mysql !TGT! error"
  >>"%TMPREC%" echo mysql,!TGT!,,error: alter/set password failed
) else (
  "%MBIN%" -u %MYUSER% -h %MYHOST% --protocol=TCP -N -B -e "FLUSH PRIVILEGES" >nul 2>&1
  call :log "+" "mysql !TGT! changed"
  >>"%TMPREC%" echo mysql,!TGT!,!PW!,changed
)
goto :eof

:resolve_mysql
set "MBIN="
if defined MYSQLBIN ( set "MBIN=%MYSQLBIN%" & goto :eof )
where mysql >nul 2>&1 && ( set "MBIN=mysql" & goto :eof )
for %%p in (
  "C:\xampp\mysql\bin\mysql.exe"
) do if exist "%%~p" ( set "MBIN=%%~p" & goto :eof )
for /d %%d in ("C:\Program Files\MySQL\MySQL Server *") do if exist "%%~d\bin\mysql.exe" ( set "MBIN=%%~d\bin\mysql.exe" & goto :eof )
for /d %%d in ("C:\Program Files\MariaDB *") do if exist "%%~d\bin\mysql.exe" ( set "MBIN=%%~d\bin\mysql.exe" & goto :eof )
goto :eof

rem ============================================================ WordPress ======
:do_wordpress
set "WPDIR=%WPPATH%"
if not defined WPDIR call :find_wp
if not defined WPDIR (
  call :log "-" "wordpress - skipped: no wp-config.php found (pass /wppath)"
  >>"%TMPREC%" echo wordpress,-,,skipped: no wp-config.php found
  goto :eof
)
set "CFG=%WPDIR%\wp-config.php"
call :genpw %LENGTH%
if "%DRYRUN%"=="1" (
  call :log "+" "wordpress %WPADMIN% @ %WPDIR% dry-run"
  >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,!PW!,dry-run
  goto :eof
)
where wp >nul 2>&1 && (
  wp user update %WPADMIN% --user_pass=!PW! --path="%WPDIR%" >nul 2>&1 && (
    call :log "+" "wordpress %WPADMIN% changed (wp-cli)"
    >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,!PW!,changed (wp-cli)
    goto :eof
  )
)
rem DB fallback (single-quoted defines).
call :wpdef DB_NAME & set "DBNAME=!WPVAL!"
call :wpdef DB_USER & set "DBUSER=!WPVAL!"
call :wpdef DB_PASSWORD & set "DBPASS=!WPVAL!"
call :wpdef DB_HOST & set "DBHOST=!WPVAL!"
if not defined DBHOST set "DBHOST=localhost"
set "PREFIX=wp_"
for /f "usebackq tokens=2 delims='" %%p in (`findstr /r /c:"table_prefix *= *'" "%CFG%" 2^>nul`) do set "PREFIX=%%p"
if not defined DBNAME ( >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,,error: could not parse DB credentials & call :log "-" "wordpress error: parse wp-config.php" & goto :eof )
if not defined DBUSER ( >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,,error: could not parse DB credentials & call :log "-" "wordpress error: parse wp-config.php" & goto :eof )
call :resolve_mysql
if not defined MBIN ( >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,,error: mysql client not found & call :log "-" "wordpress error: no mysql client" & goto :eof )
rem md5(PW) via certutil (hash a temp file holding the password, no newline).
set "PWF=%TEMP%\dc_wp_%RANDOM%.bin"
<nul set /p "=!PW!" > "%PWF%"
set "MD5="
for /f "skip=1 tokens=* delims=" %%h in ('certutil -hashfile "%PWF%" MD5 2^>nul') do if not defined MD5 set "MD5=%%h"
set "MD5=!MD5: =!"
del "%PWF%" >nul 2>&1
set "HOSTARG="
if /i not "%DBHOST%"=="localhost" set "HOSTARG=-h %DBHOST% --protocol=TCP"
if defined DBPASS set "MYSQL_PWD=%DBPASS%"
"%MBIN%" -u %DBUSER% %HOSTARG% %DBNAME% -N -B -e "UPDATE %PREFIX%users SET user_pass='!MD5!' WHERE user_login='%WPADMIN%'" >nul 2>&1
set "RC=%errorlevel%"
set "MYSQL_PWD="
if "%RC%"=="0" (
  call :log "+" "wordpress %WPADMIN% changed (db md5)"
  >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,!PW!,changed (db md5)
) else (
  call :log "-" "wordpress %WPADMIN% error: db update"
  >>"%TMPREC%" echo wordpress,%WPADMIN% @ %WPDIR%,,error: db update failed
)
goto :eof

:find_wp
set "WPDIR="
for %%r in ("C:\inetpub\wwwroot" "C:\xampp\htdocs" "C:\wamp64\www" "C:\wamp\www") do (
  if exist "%%~r\wp-config.php" ( set "WPDIR=%%~r" & goto :eof )
  if exist "%%~r" for /d %%s in ("%%~r\*") do if exist "%%~s\wp-config.php" ( set "WPDIR=%%~s" & goto :eof )
)
goto :eof

:wpdef
set "WPVAL="
for /f "usebackq tokens=4 delims='" %%a in (`findstr /r /c:"define.*'%~1'" "%CFG%" 2^>nul`) do if not defined WPVAL set "WPVAL=%%a"
goto :eof

rem ================================================================ Gitea ======
:do_gitea
call :resolve_gitea
if not defined GBIN (
  call :log "-" "gitea - skipped: binary not found (pass /giteabin)"
  >>"%TMPREC%" echo gitea,-,,skipped: gitea binary not found
  goto :eof
)
if not defined GITEAADMIN (
  call :log "-" "gitea - skipped: no admin username (pass /giteaadmin <user>)"
  >>"%TMPREC%" echo gitea,-,,skipped: no admin username given
  goto :eof
)
call :genpw %LENGTH%
if "%DRYRUN%"=="1" (
  call :log "+" "gitea %GITEAADMIN% dry-run"
  >>"%TMPREC%" echo gitea,%GITEAADMIN%,!PW!,dry-run
  goto :eof
)
set "GCFG="
call :resolve_gitea_conf
if defined GITEACONF set "GCFG=--config "%GITEACONF%""
"%GBIN%" admin user change-password --username %GITEAADMIN% --password !PW! %GCFG% >nul 2>&1
if errorlevel 1 "%GBIN%" admin change-password --username %GITEAADMIN% --password !PW! %GCFG% >nul 2>&1
if errorlevel 1 (
  call :log "-" "gitea %GITEAADMIN% error"
  >>"%TMPREC%" echo gitea,%GITEAADMIN%,,error: change-password failed
) else (
  call :log "+" "gitea %GITEAADMIN% changed"
  >>"%TMPREC%" echo gitea,%GITEAADMIN%,!PW!,changed
)
goto :eof

:resolve_gitea
set "GBIN="
if defined GITEABIN ( set "GBIN=%GITEABIN%" & goto :eof )
where gitea >nul 2>&1 && ( set "GBIN=gitea" & goto :eof )
for %%p in ("C:\gitea\gitea.exe" "C:\Program Files\Gitea\gitea.exe") do if exist "%%~p" ( set "GBIN=%%~p" & goto :eof )
goto :eof

:resolve_gitea_conf
if defined GITEACONF goto :eof
for %%p in ("C:\gitea\custom\conf\app.ini" "C:\Program Files\Gitea\custom\conf\app.ini") do if exist "%%~p" ( set "GITEACONF=%%~p" & goto :eof )
goto :eof

rem --------------------------------------------------------------- helpers ---
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

:tolowervar
call :tolowervar2 %~1 %~1
goto :eof
:tolowervar2
setlocal EnableDelayedExpansion
set "s=!%~1!"
for %%A in ("A=a" "B=b" "C=c" "D=d" "E=e" "F=f" "G=g" "H=h" "I=i" "J=j" "K=k" "L=l" "M=m" "N=n" "O=o" "P=p" "Q=q" "R=r" "S=s" "T=t" "U=u" "V=v" "W=w" "X=x" "Y=y" "Z=z") do set "s=!s:%%~A!"
endlocal & set "%~2=%s%"
goto :eof

:log
echo [%TIME:~0,8%] [%~1] %~2 1>&2
goto :eof
