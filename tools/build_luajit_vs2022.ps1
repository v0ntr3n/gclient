#Requires -Version 5.1
<#
.SYNOPSIS
    Reproducible Visual Studio 2022 (MSVC v143, Win32 x86, /MD Release + PDB) source build
    for LuaJIT 2.0.1, eliminating the obsolete VS2010 MSVCR100.dll prebuilt dependency.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CocosRoot = (Join-Path $PSScriptRoot "..\external\cocos2d-x-2.2.6"),

    [Parameter(Mandatory = $false)]
    [string]$LuaJitSourceDir = "",

    [Parameter(Mandatory = $false)]
    [string]$SourceArchivePath = "",

    [Parameter(Mandatory = $false)]
    [string]$GitRepoUrl = "https://github.com/openresty/luajit2.git",

    [Parameter(Mandatory = $false)]
    [string]$GitRef = "v2.0.1",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedCommitSha = "",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedArchiveSha256 = "",

    [Parameter(Mandatory = $false)]
    [string]$BuildWorkDir = (Join-Path $PSScriptRoot "..\build\luajit-2.0.1-v143-x86"),

    [Parameter(Mandatory = $false)]
    [string]$ProvenanceOut = (Join-Path $PSScriptRoot "..\build\luajit-provenance.json"),

    [Parameter(Mandatory = $false)]
    [string]$AppOutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "[LuaJIT-v143] $Message" -ForegroundColor Cyan
}

function Resolve-VcVars32 {
    $candidates = @()
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installPath = & $vswhere -version "[17.0,18.0)" -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installPath)) {
            $candidates += (Join-Path $installPath.Trim() "VC\Auxiliary\Build\vcvars32.bat")
        }
    }
    foreach ($ed in @("Enterprise", "Professional", "Community", "BuildTools")) {
        $candidates += "C:\Program Files\Microsoft Visual Studio\2022\$ed\VC\Auxiliary\Build\vcvars32.bat"
    }
    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath $cand) {
            return (Resolve-Path -LiteralPath $cand).Path
        }
    }
    throw "Unable to locate Visual Studio 2022 vcvars32.bat (MSVC v143 x86 toolset required)."
}

function Assert-LuaJit201Header([string]$HeaderPath) {
    if (-not (Test-Path -LiteralPath $HeaderPath)) {
        throw "Missing luajit.h at '$HeaderPath'."
    }
    $content = Get-Content -LiteralPath $HeaderPath -Raw -Encoding UTF8
    if ($content -notmatch '#define\s+LUAJIT_VERSION\s+"LuaJIT 2\.0\.1"') {
        throw "Version mismatch in '$HeaderPath': expected LUAJIT_VERSION `"LuaJIT 2.0.1`"."
    }
    if ($content -notmatch '#define\s+LUAJIT_VERSION_NUM\s+20001\b') {
        throw "Version mismatch in '$HeaderPath': expected LUAJIT_VERSION_NUM 20001."
    }
}

# 1. Verify Cocos2d-x root & bundled LuaJIT 2.0.1 header contract
$CocosRootFull = [System.IO.Path]::GetFullPath($CocosRoot)
if (-not (Test-Path -LiteralPath $CocosRootFull)) {
    throw "Cocos2d-x root not found at '$CocosRootFull'. Fetch Cocos2d-x 2.2.6 first."
}
$CocosLuaJitInclude = Join-Path $CocosRootFull "scripting\lua\luajit\include"
$CocosLuaJitHeader  = Join-Path $CocosLuaJitInclude "luajit.h"
if (Test-Path -LiteralPath $CocosLuaJitHeader) {
    Assert-LuaJit201Header -HeaderPath $CocosLuaJitHeader
    Write-Step "Verified Cocos2d-x header contract: LUAJIT_VERSION 'LuaJIT 2.0.1' (20001)."
}

# 2. Acquire pinned LuaJIT 2.0.1 source into clean working directory
$WorkRoot = [System.IO.Path]::GetFullPath($BuildWorkDir)
if (Test-Path -LiteralPath $WorkRoot) {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
$StagedRoot = Join-Path $WorkRoot "LuaJIT-2.0.1"

$SourceKind = ""
$SourceCommitSha = ""
$SourceArchiveSha256 = ""

$BundledLuaJitDir = Join-Path $CocosRootFull "scripting\lua\luajit\LuaJIT-2.0.1"
if (-not [string]::IsNullOrWhiteSpace($LuaJitSourceDir)) {
    $ResolvedSrc = (Resolve-Path -LiteralPath $LuaJitSourceDir).Path
    $SourceKind = "local_dir:$ResolvedSrc"
    Write-Step "Using explicit LuaJIT source directory: $ResolvedSrc"
    Copy-Item -LiteralPath $ResolvedSrc -Destination $StagedRoot -Recurse -Force
} elseif (-not [string]::IsNullOrWhiteSpace($SourceArchivePath)) {
    $ResolvedArchive = (Resolve-Path -LiteralPath $SourceArchivePath).Path
    $SourceArchiveSha256 = (Get-FileHash -LiteralPath $ResolvedArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $SourceKind = "archive:$ResolvedArchive"
    Write-Step "Source archive SHA-256: $SourceArchiveSha256"
    if (-not [string]::IsNullOrWhiteSpace($ExpectedArchiveSha256) -and
        $SourceArchiveSha256 -ne $ExpectedArchiveSha256.Trim().ToLowerInvariant()) {
        throw "Archive SHA-256 mismatch! Expected '$ExpectedArchiveSha256', got '$SourceArchiveSha256'."
    }
    $extractTmp = Join-Path $WorkRoot "archive-extract"
    New-Item -ItemType Directory -Path $extractTmp -Force | Out-Null
    & tar.exe -xf $ResolvedArchive -C $extractTmp
    if ($LASTEXITCODE -ne 0) {
        throw "tar.exe failed extracting '$ResolvedArchive' (exit $LASTEXITCODE)."
    }
    $subDir = Get-ChildItem -LiteralPath $extractTmp -Directory | Select-Object -First 1
    if ($null -eq $subDir) {
        throw "Archive '$ResolvedArchive' did not contain a top-level directory."
    }
    Move-Item -LiteralPath $subDir.FullName -Destination $StagedRoot
} elseif (Test-Path -LiteralPath (Join-Path $BundledLuaJitDir "src\msvcbuild.bat")) {
    $SourceKind = "cocos2dx_bundled:$BundledLuaJitDir"
    Write-Step "Using LuaJIT-2.0.1 source bundled inside Cocos2d-x: $BundledLuaJitDir"
    Copy-Item -LiteralPath $BundledLuaJitDir -Destination $StagedRoot -Recurse -Force
} else {
    $SourceKind = "git:$GitRepoUrl#$GitRef"
    Write-Step "Cloning preserved tag '$GitRef' from '$GitRepoUrl'..."
    & git.exe clone --branch $GitRef --depth 1 --config core.autocrlf=false $GitRepoUrl $StagedRoot
    if ($LASTEXITCODE -ne 0) {
        throw "git clone failed for '$GitRepoUrl' ref '$GitRef' (exit $LASTEXITCODE)."
    }
    $SourceCommitSha = (& git.exe -C $StagedRoot rev-parse --verify "HEAD^{commit}").Trim().ToLowerInvariant()
    Write-Step "Checked out Git commit SHA-1: $SourceCommitSha (tag: $GitRef)"
    if (-not [string]::IsNullOrWhiteSpace($ExpectedCommitSha) -and
        $SourceCommitSha -ne $ExpectedCommitSha.Trim().ToLowerInvariant()) {
        throw "Git commit SHA mismatch! Expected '$ExpectedCommitSha', got '$SourceCommitSha'."
    }
}

$SrcDir = Join-Path $StagedRoot "src"
Assert-LuaJit201Header -HeaderPath (Join-Path $SrcDir "luajit.h")

# 3. Apply minimal documented MSVC v143 + Windows 10/11 UCRT patches
Write-Step "Applying minimal MSVC v143 UCRT patches (snprintf guard + /MD Release + /Zi PDB)..."
foreach ($relHeader in @("host\buildvm.h", "lj_def.h")) {
    $hdrFile = Join-Path $SrcDir $relHeader
    if (Test-Path -LiteralPath $hdrFile) {
        $raw = Get-Content -LiteralPath $hdrFile -Raw -Encoding UTF8
        $patched = [regex]::Replace(
            $raw,
            '(?m)^[ \t]*#[ \t]*define[ \t]+snprintf[ \t]+_snprintf\b',
            "#if !defined(snprintf) && (!defined(_MSC_VER) || _MSC_VER < 1900)`r`n#define snprintf _snprintf`r`n#endif"
        )
        if ($patched -ne $raw) {
            [System.IO.File]::WriteAllText($hdrFile, $patched, (New-Object System.Text.UTF8Encoding($false)))
            Write-Step "Patched UCRT snprintf macro guard in src/$relHeader"
        }
    }
}

$MsvcBuildBat = Join-Path $SrcDir "msvcbuild.bat"
if (-not (Test-Path -LiteralPath $MsvcBuildBat)) {
    throw "Missing src/msvcbuild.bat in '$SrcDir'."
}
$batText = (Get-Content -LiteralPath $MsvcBuildBat -Raw -Encoding UTF8) -replace "`r`n", "`n"
$batText = [regex]::Replace(
    $batText,
    '(?m)^@set[ \t]+LJCOMPILE=[^\r\n]*$',
    '@set LJCOMPILE=cl /nologo /c /O2 /W3 /Zi /FS /MD /D_CRT_SECURE_NO_DEPRECATE'
)
$batText = [regex]::Replace(
    $batText,
    '(?m)^@set[ \t]+LJLINK=[^\r\n]*$',
    '@set LJLINK=link /nologo /DEBUG /OPT:REF /OPT:ICF'
)
$batText = [regex]::Replace(
    $batText,
    '(?m)%LJLINK%[ \t]+/DLL[ \t]+/out:%LJDLLNAME%[ \t]+([^\r\n]*)$',
    '%LJLINK% /DLL /PDB:lua51.pdb /IMPLIB:%LJLIBNAME% /out:%LJDLLNAME% $1'
)
$batText = [regex]::Replace(
    $batText,
    '(?m)^@?(%LJMT%[ \t]+-manifest[ \t]+([^\s\r\n]+)[ \t]+[^\r\n]*)$',
    '@if exist $2 $1'
)
$batText = $batText -replace "`n", "`r`n"
[System.IO.File]::WriteAllText($MsvcBuildBat, $batText, [System.Text.Encoding]::ASCII)

# 4. Purge stale VS2010 MSVCR100 prebuilts BEFORE building
$CocosLuaJitWin32 = Join-Path $CocosRootFull "scripting\lua\luajit\win32"
New-Item -ItemType Directory -Path $CocosLuaJitWin32 -Force | Out-Null
foreach ($stale in @(
    (Join-Path $CocosLuaJitWin32 "lua51.dll"),
    (Join-Path $CocosLuaJitWin32 "lua51.lib"),
    (Join-Path $CocosLuaJitWin32 "lua51.pdb"),
    (Join-Path $CocosLuaJitWin32 "luajit.exe"),
    (Join-Path $CocosRootFull "Release.win32\lua51.dll"),
    (Join-Path $CocosRootFull "Release.win32\lua51.lib"),
    (Join-Path $CocosRootFull "Release.win32\liblua.lib")
)) {
    if (Test-Path -LiteralPath $stale) {
        Remove-Item -LiteralPath $stale -Force
        Write-Step "Removed stale prebuilt binary: $stale"
    }
}

# 5. Compile LuaJIT 2.0.1 x86 via VS2022 vcvars32.bat and explicitly verify cl.exe >= 19.30 (v143)
$VcVars32 = Resolve-VcVars32
Write-Step "Building LuaJIT 2.0.1 x86 (/MD Release + PDB) via: $VcVars32"

$ClCheckCmdPath = Join-Path $WorkRoot "check_cl_x86.cmd"
@(
    "@echo off",
    "call `"$VcVars32`" >nul 2>&1",
    "if errorlevel 1 exit /b %errorlevel%",
    "cl.exe 2>&1",
    "exit /b 0"
) -join "`r`n" | Set-Content -LiteralPath $ClCheckCmdPath -Encoding ASCII

$clCheckOut = (& cmd.exe /d /c $ClCheckCmdPath) -join "`n"
Write-Host $clCheckOut
if ($clCheckOut -notmatch 'Version\s+(19\.[34]\d\.\d+).*for\s+x86') {
    throw "Compiler verification failed: expected MSVC v143 (19.3x/19.4x) for x86, got: $clCheckOut"
}
$MsvcCompilerVersion = $Matches[1]

$BuildWrapperCmdPath = Join-Path $WorkRoot "run_msvcbuild_x86.cmd"
@(
    "@echo off",
    "call `"$VcVars32`" >nul 2>&1",
    "if errorlevel 1 exit /b %errorlevel%",
    "cd /d `"$SrcDir`"",
    "if errorlevel 1 exit /b %errorlevel%",
    "call msvcbuild.bat 2>&1",
    "exit /b %errorlevel%"
) -join "`r`n" | Set-Content -LiteralPath $BuildWrapperCmdPath -Encoding ASCII

& cmd.exe /d /c $BuildWrapperCmdPath
if ($LASTEXITCODE -ne 0) {
    throw "msvcbuild.bat failed with exit code $LASTEXITCODE."
}

$BuiltDll = Join-Path $SrcDir "lua51.dll"
$BuiltLib = Join-Path $SrcDir "lua51.lib"
$BuiltPdb = Join-Path $SrcDir "lua51.pdb"
$BuiltExe = Join-Path $SrcDir "luajit.exe"
foreach ($artifact in @($BuiltDll, $BuiltLib, $BuiltPdb, $BuiltExe)) {
    if (-not (Test-Path -LiteralPath $artifact) -or (Get-Item -LiteralPath $artifact).Length -eq 0) {
        throw "Expected LuaJIT output missing or empty: $artifact"
    }
}

# 6. Validate lua51.dll with dumpbin /headers, /dependents, /imports, /exports
$DumpbinCmdPath = Join-Path $WorkRoot "run_dumpbin_x86.cmd"
@(
    "@echo off",
    "call `"$VcVars32`" >nul 2>&1",
    "if errorlevel 1 exit /b %errorlevel%",
    "dumpbin %1 `"%~2`" 2>&1",
    "exit /b %errorlevel%"
) -join "`r`n" | Set-Content -LiteralPath $DumpbinCmdPath -Encoding ASCII

$hdrOut = (& cmd.exe /d /c $DumpbinCmdPath /headers $BuiltDll) -join "`n"
$depOut = (& cmd.exe /d /c $DumpbinCmdPath /dependents $BuiltDll) -join "`n"
$impOut = (& cmd.exe /d /c $DumpbinCmdPath /imports $BuiltDll) -join "`n"
$expOut = (& cmd.exe /d /c $DumpbinCmdPath /exports $BuiltDll) -join "`n"

if ($hdrOut -notmatch '14C\s+machine\s+\(x86\)') {
    throw "dumpbin /headers failed: lua51.dll is not IMAGE_FILE_MACHINE_I386 (0x14C)."
}
if ($hdrOut -notmatch 'lua51\.pdb') {
    throw "dumpbin /headers failed: lua51.dll missing RSDS debug reference to lua51.pdb."
}

foreach ($forbidden in @(
    "MSVCR80.dll", "MSVCR90.dll", "MSVCR100.dll", "MSVCR100D.dll", "MSVCR110.dll", "MSVCR120.dll",
    "MSVCP100.dll", "MSVCP110.dll", "MSVCP120.dll", "VCRUNTIME140D.dll", "ucrtbased.dll", "MSVCP140D.dll"
)) {
    if ($depOut -match [regex]::Escape($forbidden) -or $impOut -match [regex]::Escape($forbidden)) {
        throw "dumpbin /dependents failed: lua51.dll imports prohibited runtime '$forbidden'!"
    }
}
if ($depOut -notmatch '(?i)VCRUNTIME140\.dll' -or $depOut -notmatch '(?i)(api-ms-win-crt-|ucrtbase\.dll)') {
    throw "dumpbin /dependents failed: lua51.dll does not import modern VC++ v143 dynamic CRT (/MD)."
}

$requiredExports = @(
    "luaL_newstate", "luaL_openlibs", "luaL_loadbuffer", "luaL_loadstring", "luaL_ref", "luaL_unref",
    "lua_close", "lua_pcall", "lua_cpcall", "lua_call", "lua_pushcclosure", "lua_pushlstring",
    "lua_tolstring", "lua_tonumber", "lua_tointeger", "lua_createtable", "lua_getfield", "lua_setfield",
    "lua_newuserdata", "lua_setmetatable", "lua_getstack", "lua_getinfo", "lua_gc", "luaJIT_setmode"
)
foreach ($sym in $requiredExports) {
    if ($expOut -notmatch "\b$([regex]::Escape($sym))\b") {
        throw "dumpbin /exports failed: required Lua/LuaJIT C API export '$sym' missing from lua51.dll!"
    }
}

$VerCmdPath = Join-Path $WorkRoot "run_luajit_ver.cmd"
@(
    "@echo off",
    "`"%~1`" -v 2>&1",
    "exit /b %errorlevel%"
) -join "`r`n" | Set-Content -LiteralPath $VerCmdPath -Encoding ASCII
$verOut = (& cmd.exe /d /c $VerCmdPath $BuiltExe) -join " "
if ($LASTEXITCODE -ne 0 -or $verOut -notmatch 'LuaJIT 2\.0\.1') {
    throw "luajit.exe -v verification failed: $verOut"
}

$DllSha256 = (Get-FileHash -LiteralPath $BuiltDll -Algorithm SHA256).Hash.ToLowerInvariant()
$LibSha256 = (Get-FileHash -LiteralPath $BuiltLib -Algorithm SHA256).Hash.ToLowerInvariant()
$PdbSha256 = (Get-FileHash -LiteralPath $BuiltPdb -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Step "Verified $verOut | MSVC=$MsvcCompilerVersion | lua51.dll SHA256=$DllSha256"

# 7. Stage freshly built v143 binaries & headers into Cocos2d-x
Copy-Item -LiteralPath $BuiltDll -Destination (Join-Path $CocosLuaJitWin32 "lua51.dll") -Force
Copy-Item -LiteralPath $BuiltLib -Destination (Join-Path $CocosLuaJitWin32 "lua51.lib") -Force
Copy-Item -LiteralPath $BuiltPdb -Destination (Join-Path $CocosLuaJitWin32 "lua51.pdb") -Force
Set-Content -LiteralPath (Join-Path $CocosLuaJitWin32 "luajit-v143-built.marker") -Value $DllSha256 -Encoding ASCII
Copy-Item -LiteralPath $BuiltExe -Destination (Join-Path $CocosLuaJitWin32 "luajit.exe") -Force

New-Item -ItemType Directory -Path $CocosLuaJitInclude -Force | Out-Null
foreach ($hdr in @("lua.h", "luaconf.h", "lualib.h", "lauxlib.h", "lua.hpp", "luajit.h")) {
    $srcHdr = Join-Path $SrcDir $hdr
    if (Test-Path -LiteralPath $srcHdr) {
        Copy-Item -LiteralPath $srcHdr -Destination (Join-Path $CocosLuaJitInclude $hdr) -Force
    }
}

if (-not [string]::IsNullOrWhiteSpace($ProvenanceOut)) {
    $provDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($ProvenanceOut))
    New-Item -ItemType Directory -Path $provDir -Force | Out-Null
    $provObj = [ordered]@{
        luajit_version      = "LuaJIT 2.0.1"
        luajit_version_num  = 20001
        architecture        = "IMAGE_FILE_MACHINE_I386"
        toolset             = "v143"
        msvc_cl_version     = $MsvcCompilerVersion
        crt_linkage         = "/MD"
        source_provenance   = $SourceKind
        source_commit_sha   = $SourceCommitSha
        source_archive_sha  = $SourceArchiveSha256
        lua51_dll_sha256    = $DllSha256
        lua51_lib_sha256    = $LibSha256
        lua51_pdb_sha256    = $PdbSha256
        built_at_utc        = (Get-Date).ToUniversalTime().ToString("o")
    }
    $provObj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ProvenanceOut -Encoding UTF8
    Write-Step "Wrote LuaJIT provenance manifest: $ProvenanceOut"
}

if (-not [string]::IsNullOrWhiteSpace($AppOutputDir)) {
    $OutFull = [System.IO.Path]::GetFullPath($AppOutputDir)
    New-Item -ItemType Directory -Path $OutFull -Force | Out-Null
    Copy-Item -LiteralPath $BuiltDll -Destination (Join-Path $OutFull "lua51.dll") -Force
    Copy-Item -LiteralPath $BuiltPdb -Destination (Join-Path $OutFull "lua51.pdb") -Force
}
