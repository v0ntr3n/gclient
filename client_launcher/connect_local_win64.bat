@echo off
setlocal EnableExtensions
REM Kestrel Canvas (Axmol v2.11.5 x64) + Cobalt Relay Local Launcher (Win64)

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

if /I "%~1"=="--orchestrate" (
    shift
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\start_kestrel_cobalt_dev.ps1" %1 %2 %3 %4 %5 %6 %7 %8 %9
    exit /b %ERRORLEVEL%
)

REM 1. Unified COBALT_* endpoint defaults (HTTP 8080 / TCP 8160)
if "%COBALT_HTTP_HOST%"==""   set "COBALT_HTTP_HOST=127.0.0.1"
if "%COBALT_HTTP_PORT%"==""   set "COBALT_HTTP_PORT=8080"
if "%COBALT_TCP_HOST%"==""    set "COBALT_TCP_HOST=127.0.0.1"
if "%COBALT_TCP_PORT%"==""    set "COBALT_TCP_PORT=8160"
if "%COBALT_PUBLIC_HOST%"=="" set "COBALT_PUBLIC_HOST=127.0.0.1"
set "COBALT_HTTP_ADDR=%COBALT_HTTP_HOST%:%COBALT_HTTP_PORT%"
set "COBALT_TCP_ADDR=%COBALT_TCP_HOST%:%COBALT_TCP_PORT%"
if "%COBALT_HTTP_URL%"=="" (
    if not "%GCLIENT_HTTP_HOST%"=="" (set "COBALT_HTTP_URL=%GCLIENT_HTTP_HOST%") else (set "COBALT_HTTP_URL=http://%COBALT_HTTP_ADDR%")
)
set "COBALT_HEALTHZ_URL=%COBALT_HTTP_URL%/healthz"

REM 2. Auto-discover 64-bit Axmol GCLIENT.exe
if "%KESTREL_EXE_PATH%"=="" if not "%GCLIENT_EXE_PATH%"=="" set "KESTREL_EXE_PATH=%GCLIENT_EXE_PATH%"
if "%KESTREL_EXE_PATH%"=="" (
    for %%P in ("%SCRIPT_DIR%\..\GCLIENT.exe" "%SCRIPT_DIR%\..\..\kestrel-canvas\build\bin\Release\GCLIENT.exe" "%SCRIPT_DIR%\..\..\kestrel-canvas\build\bin\GCLIENT\Release\GCLIENT.exe" "%SCRIPT_DIR%\..\..\kestrel-canvas\build_win64\bin\Release\GCLIENT.exe" "%SCRIPT_DIR%\..\kestrel-canvas\build\bin\Release\GCLIENT.exe" "%CD%\build\bin\Release\GCLIENT.exe" "%CD%\GCLIENT.exe") do (
        if "%KESTREL_EXE_PATH%"=="" if exist "%%~fP" set "KESTREL_EXE_PATH=%%~fP"
    )
)
if "%KESTREL_EXE_PATH%"=="" (
    echo [ERROR] 64-bit GCLIENT.exe not found. Set KESTREL_EXE_PATH=C:\path\to\GCLIENT.exe and re-run.
    exit /b 1
)
if not exist "%KESTREL_EXE_PATH%" (
    echo [ERROR] KESTREL_EXE_PATH does not exist: "%KESTREL_EXE_PATH%"
    exit /b 1
)
for %%F in ("%KESTREL_EXE_PATH%") do set "CLIENT_ROOT=%%~dpF"
if "%CLIENT_ROOT:~-1%"=="\" set "CLIENT_ROOT=%CLIENT_ROOT:~0,-1%"

REM 3. Auto-discover Resources_Axmol_Converted (with scripts\main.lua)
if "%KESTREL_RESOURCES_DIR%"=="" if not "%GCLIENT_RESOURCES_DIR%"=="" set "KESTREL_RESOURCES_DIR=%GCLIENT_RESOURCES_DIR%"
if "%KESTREL_RESOURCES_DIR%"=="" if not "%GCLIENT_GAME_ASSETS%"==""   set "KESTREL_RESOURCES_DIR=%GCLIENT_GAME_ASSETS%"
if "%KESTREL_RESOURCES_DIR%"=="" (
    for %%R in ("%CLIENT_ROOT%\Resources_Axmol_Converted" "%CLIENT_ROOT%\Resources" "%CLIENT_ROOT%\..\..\..\Resources_Axmol_Converted" "%CLIENT_ROOT%\..\..\..\OMG3Q_Resources\Resources_Axmol_Converted" "%CLIENT_ROOT%\..\..\..\..\Resources_Axmol_Converted" "%CLIENT_ROOT%\..\..\..\..\OMG3Q_Resources\Resources_Axmol_Converted" "%SCRIPT_DIR%\..\..\Resources_Axmol_Converted" "%SCRIPT_DIR%\..\..\OMG3Q_Resources\Resources_Axmol_Converted") do (
        if "%KESTREL_RESOURCES_DIR%"=="" if exist "%%~fR\scripts\main.lua" set "KESTREL_RESOURCES_DIR=%%~fR"
    )
)
if "%KESTREL_RESOURCES_DIR%"=="" (
    echo [ERROR] Resources_Axmol_Converted with scripts\main.lua not found. Set KESTREL_RESOURCES_DIR and re-run.
    exit /b 1
)

if /I "%~1"=="--restore" (
    for %%C in (game_config.json config.json) do (
        if exist "%KESTREL_RESOURCES_DIR%\platform\%%C.orig.bak" move /Y "%KESTREL_RESOURCES_DIR%\platform\%%C.orig.bak" "%KESTREL_RESOURCES_DIR%\platform\%%C" >nul
    )
    echo [connect_local_win64] Restored original platform config files under "%KESTREL_RESOURCES_DIR%\platform".
    exit /b 0
)

REM 4. Isolate Axmol x64 profile & write plaintext JSON overrides (base-assets + hotfix mirror)
if "%KESTREL_PROFILE_DIR%"=="" set "KESTREL_PROFILE_DIR=%LOCALAPPDATA%\GCLIENT_AXMOL\profiles\cobalt_local_dev"
set "KESTREL_WRITABLE_DIR=%KESTREL_PROFILE_DIR%\writable"
set "KESTREL_HOTFIX_DIR=%KESTREL_WRITABLE_DIR%\hotfix"
set "KESTREL_BASE_ASSETS_DIR=%KESTREL_PROFILE_DIR%\platform_override"
set "KESTREL_SESSION_FILE=%KESTREL_PROFILE_DIR%\account_session.json"
set "KESTREL_UUID_FILE=%KESTREL_PROFILE_DIR%\device_uuid.txt"
for %%M in ("%KESTREL_BASE_ASSETS_DIR%\platform" "%KESTREL_HOTFIX_DIR%\platform" "%KESTREL_PROFILE_DIR%\logs" "%KESTREL_PROFILE_DIR%\dumps") do (
    if not exist "%%~M" mkdir "%%~M"
)

for %%D in ("%KESTREL_BASE_ASSETS_DIR%\platform" "%KESTREL_HOTFIX_DIR%\platform") do (
    echo {"host":"%COBALT_HTTP_URL%","host_debug":"%COBALT_HTTP_URL%","log_host":"%COBALT_HTTP_URL%","log_host_debug":"%COBALT_HTTP_URL%","pushurl":"%COBALT_HTTP_URL%/push","gn":"vnsg2","language":"vi_VN"}> "%%~D\game_config.json"
    echo {"pl":"vngandroid","os":"android","gn":"vnsg2","key":"2A0ce68806G8aJ58Mo6_vnsg2@OmZHv","userCenterName":"Win64AxmolLocal","userUrl":"%COBALT_HTTP_URL%","auth_secret":"d345c6c5c29669eae007b682625fbf42","gameID":"GCLIENT","debug":"0","isAd":"0","isStandAlone":"0","isSimulation":"0","simulateHashHost":"%COBALT_HTTP_URL%"}> "%%~D\config.json"
)

if /I "%~1"=="--swap-in-place" (
    if not exist "%KESTREL_RESOURCES_DIR%\platform" mkdir "%KESTREL_RESOURCES_DIR%\platform"
    for %%C in (game_config.json config.json) do (
        if exist "%KESTREL_RESOURCES_DIR%\platform\%%C" if not exist "%KESTREL_RESOURCES_DIR%\platform\%%C.orig.bak" copy /Y "%KESTREL_RESOURCES_DIR%\platform\%%C" "%KESTREL_RESOURCES_DIR%\platform\%%C.orig.bak" >nul
        copy /Y "%KESTREL_BASE_ASSETS_DIR%\platform\%%C" "%KESTREL_RESOURCES_DIR%\platform\%%C" >nul
    )
    echo [connect_local_win64] Installed plaintext overrides in "%KESTREL_RESOURCES_DIR%\platform".
    shift
)

REM 5. Auto-boot cobalt-relay (gserver.exe) if /healthz is not yet responding
where curl.exe >nul 2>&1
if "%ERRORLEVEL%"=="0" (
    curl.exe -fsS --max-time 2 "%COBALT_HEALTHZ_URL%" >nul 2>&1 || curl.exe -fsS --max-time 2 "%COBALT_HTTP_URL%/admin/status" >nul 2>&1
    if not "%ERRORLEVEL%"=="0" (
        if "%COBALT_RELAY_BIN%"=="" (
            for %%S in ("%SCRIPT_DIR%\..\target\release\gserver.exe" "%SCRIPT_DIR%\..\target\debug\gserver.exe" "%SCRIPT_DIR%\target\release\gserver.exe" "%SCRIPT_DIR%\..\..\cobalt-relay\target\release\gserver.exe") do (
                if "%COBALT_RELAY_BIN%"=="" if exist "%%~fS" set "COBALT_RELAY_BIN=%%~fS"
            )
        )
        if not "%COBALT_RELAY_BIN%"=="" if exist "%COBALT_RELAY_BIN%" (
            if "%COBALT_DATA_DIR%"=="" set "COBALT_DATA_DIR=%SCRIPT_DIR%\..\data"
            echo [connect_local_win64] Starting cobalt-relay: "%COBALT_RELAY_BIN%"
            start "cobalt-relay" /MIN "%COBALT_RELAY_BIN%" --http-addr "%COBALT_HTTP_ADDR%" --tcp-addr "%COBALT_TCP_ADDR%" --public-host "%COBALT_PUBLIC_HOST%" --data-dir "%COBALT_DATA_DIR%" --print-bound-addrs
        )
        echo [connect_local_win64] Waiting for %COBALT_HEALTHZ_URL% readiness ...
        set /A "_TRIES=0"
        :WAIT_HEALTHZ
        set /A "_TRIES+=1"
        curl.exe -fsS --max-time 2 "%COBALT_HEALTHZ_URL%" >nul 2>&1 && goto :HEALTHZ_OK
        curl.exe -fsS --max-time 2 "%COBALT_HTTP_URL%/admin/status" >nul 2>&1 && goto :HEALTHZ_OK
        if %_TRIES% GEQ 20 (
            echo [ERROR] cobalt-relay did not respond at %COBALT_HEALTHZ_URL% after 20 attempts.
            exit /b 1
        )
        ping -n 2 127.0.0.1 >nul
        goto :WAIT_HEALTHZ
        :HEALTHZ_OK
        echo [connect_local_win64] cobalt-relay health check PASSED.
    )
)

REM 6. Clear stale cookie jar & export KESTREL_* / GCLIENT_* environment contract
if exist "%KESTREL_WRITABLE_DIR%\sdk_cookies.txt" del /F /Q "%KESTREL_WRITABLE_DIR%\sdk_cookies.txt" >nul 2>&1
if "%KESTREL_ACCOUNT_PID%"==""   set "KESTREL_ACCOUNT_PID=1243831974477471744"
if "%KESTREL_ACCOUNT_TOKEN%"=="" set "KESTREL_ACCOUNT_TOKEN=SID_56921a50f34cf49824123bfd56a62d70bb1e51795440318446"
if "%KESTREL_AUTH_SECRET%"==""   set "KESTREL_AUTH_SECRET=d345c6c5c29669eae007b682625fbf42"
set "KESTREL_AUTH_URL=%COBALT_HTTP_URL%"
set "KESTREL_INSECURE_TLS=1"
set "GCLIENT_HTTP_HOST=%COBALT_HTTP_URL%"
set "GCLIENT_AUTH_URL=%KESTREL_AUTH_URL%"
set "GCLIENT_AUTH_SECRET=%KESTREL_AUTH_SECRET%"
set "GCLIENT_PROFILE_DIR=%KESTREL_PROFILE_DIR%"
set "GCLIENT_WRITABLE_DIR=%KESTREL_WRITABLE_DIR%"
set "GCLIENT_SESSION_FILE=%KESTREL_SESSION_FILE%"
set "GCLIENT_UUID_FILE=%KESTREL_UUID_FILE%"
set "GCLIENT_RESOURCES_DIR=%KESTREL_RESOURCES_DIR%"
set "GCLIENT_BASE_ASSETS_DIR=%KESTREL_BASE_ASSETS_DIR%"
set "GCLIENT_ASSETS_DIR=%KESTREL_BASE_ASSETS_DIR%"
set "GCLIENT_ACCOUNT_PID=%KESTREL_ACCOUNT_PID%"
set "GCLIENT_ACCOUNT_TOKEN=%KESTREL_ACCOUNT_TOKEN%"
set "GCLIENT_INSECURE_TLS=1"

echo [connect_local_win64] Launching 64-bit Axmol GCLIENT.exe -^> %COBALT_HTTP_URL%
echo   EXE            : %KESTREL_EXE_PATH%
echo   Converted Res  : %KESTREL_RESOURCES_DIR%
echo   Platform Ovrd  : %KESTREL_BASE_ASSETS_DIR% (+ hotfix mirror)
echo   Profile Dir    : %KESTREL_PROFILE_DIR%

if /I "%~1"=="--validate-assets" (
    "%KESTREL_EXE_PATH%" --validate-assets --profile-dir "%KESTREL_PROFILE_DIR%" --resources-dir "%KESTREL_RESOURCES_DIR%" --base-assets-dir "%KESTREL_BASE_ASSETS_DIR%"
    exit /b %ERRORLEVEL%
)

start "" /D "%CLIENT_ROOT%" "%KESTREL_EXE_PATH%" --profile-dir "%KESTREL_PROFILE_DIR%" --resources-dir "%KESTREL_RESOURCES_DIR%" --base-assets-dir "%KESTREL_BASE_ASSETS_DIR%" %*
