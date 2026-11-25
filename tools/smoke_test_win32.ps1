#Requires -Version 5.1
<#
.SYNOPSIS
    Deterministic Win32 process startup, --validate-assets, Unicode/space path, and crash-code
    smoke test harness for gclient-win32-release (explicitly detects headless CI WGL limits).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $ArtifactDir "smoke-test-report.json"),

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 12,

    [Parameter(Mandatory = $false)]
    [int]$Cycles = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExePath = Join-Path ([System.IO.Path]::GetFullPath($ArtifactDir)) "GCLIENT.exe"
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "GCLIENT.exe not found at '$ExePath'."
}

# Fatal Win32 NTSTATUS / exception exit codes that MUST fail CI immediately
$FatalCrashCodes = @{
    "0xC0000094" = "STATUS_INTEGER_DIVIDE_BY_ZERO"
    "0xC0000005" = "STATUS_ACCESS_VIOLATION"
    "0xC0000374" = "STATUS_HEAP_CORRUPTION"
    "0xC0000409" = "STATUS_STACK_BUFFER_OVERRUN"
    "0xC00000FD" = "STATUS_STACK_OVERFLOW"
    "0xC0000135" = "STATUS_DLL_NOT_FOUND"
    "0xC0000139" = "STATUS_ENTRYPOINT_NOT_FOUND"
    "0xC000007B" = "STATUS_INVALID_IMAGE_FORMAT"
    "0xC0000142" = "STATUS_DLL_INIT_FAILED"
}

# Detect interactive desktop / WGL availability vs Session-0 headless CI
$SessionId = (Get-Process -Id $PID).SessionId
$UserInteractive = [Environment]::UserInteractive
$VideoControllers = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$IsHeadlessSession = ($SessionId -eq 0) -or (-not $UserInteractive) -or ($env:GITHUB_ACTIONS -eq "true")

# Create a temporary smoke fixture with spaces AND Vietnamese/Japanese Unicode characters!
$SmokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) "Kestrel Smoke Tiếng Việt 日本語 $PID"
$ResDir    = Join-Path $SmokeRoot "Resources"
$ProfDir   = Join-Path $SmokeRoot "Profile Space Tiếng Việt"
New-Item -ItemType Directory -Force -Path (Join-Path $ResDir "scripts") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ResDir "platform") | Out-Null
New-Item -ItemType Directory -Force -Path $ProfDir | Out-Null

Set-Content -LiteralPath (Join-Path $ResDir "platform\config.json") -Value '{"gn":"kestrel","env":"local"}' -Encoding UTF8
Set-Content -LiteralPath (Join-Path $ResDir "scripts\main.lua") -Value @'
print("[SmokeFixture] scripts/main.lua booted cleanly under LuaJIT")
if CCDirector and CCDirector.sharedDirector then
    CCDirector:sharedDirector():end()
end
'@ -Encoding UTF8

$env:GCLIENT_HEADLESS = "1"
$env:GCLIENT_SUPPRESS_MESSAGEBOX = "1"

$Results = @()
$HardFailure = $false

function Invoke-BoundedGClient([string]$Label, [string[]]$Arguments) {
    $dumpsDir = Join-Path $ProfDir "dumps"
    if (Test-Path -LiteralPath $dumpsDir) {
        Get-ChildItem -LiteralPath $dumpsDir -Filter "*.dmp" -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.WorkingDirectory = Split-Path -Parent $ExePath
    $psi.Arguments = ($Arguments | ForEach-Object { "`"$_`"" }) -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) {
        try { $proc.Kill($true) } catch { try { $proc.Kill() } catch {} }
        $proc.WaitForExit(3000) | Out-Null
    }
    $sw.Stop()

    $stderrText = ""
    try {
        if ($stderrTask.Wait(2000)) { $stderrText = $stderrTask.Result.Trim() }
    } catch {}
    try { [void]$stdoutTask.Wait(1000) } catch {}

    $rawCode = if ($exited) { [int]$proc.ExitCode } else { -1 }
    $unsignedCode = [uint32]([BitConverter]::ToUInt32([BitConverter]::GetBytes($rawCode), 0))
    $hexCode = ("0x{0:X8}" -f $unsignedCode)
    $crashName = if ($FatalCrashCodes.ContainsKey($hexCode)) { $FatalCrashCodes[$hexCode] } else { "" }

    $dumps = @()
    if (Test-Path -LiteralPath $dumpsDir) {
        $dumps = @(Get-ChildItem -LiteralPath $dumpsDir -Filter "*.dmp" | ForEach-Object { $_.FullName })
    }

    $logsDir = Join-Path $ProfDir "logs"
    $glContextFailedInHeadless = $false
    if (Test-Path -LiteralPath $logsDir) {
        $logTxt = @(
            Get-ChildItem -LiteralPath $logsDir -Filter "*.log" -ErrorAction SilentlyContinue |
                ForEach-Object { [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8) }
        ) -join "`n"
        if ($logTxt -match "Failed to create Win32 OpenGL 2\.0 view") {
            $glContextFailedInHeadless = $true
        }
    }
    if ($stderrText -match "Failed to initialize Win32 OpenGL context|HeadlessDialogSuppressed") {
        $glContextFailedInHeadless = $true
    }

    return [ordered]@{
        label                        = $Label
        exited_within_timeout        = $exited
        duration_ms                  = [int]$sw.ElapsedMilliseconds
        exit_code                    = $rawCode
        exit_code_hex                = $hexCode
        ntstatus_crash_name          = $crashName
        minidump_count               = $dumps.Count
        headless_gl_unavailable      = $glContextFailedInHeadless
        stderr_snippet               = $stderrText
    }
}

try {
    for ($i = 1; $i -le $Cycles; $i++) {
        $valRes = Invoke-BoundedGClient -Label "validate-assets-cycle-$i" -Arguments @(
            "--validate-assets",
            "--mute",
            "--resources-dir=$ResDir",
            "--base-assets-dir=$ResDir",
            "--profile-dir=$ProfDir"
        )
        $Results += $valRes

        if (-not $valRes.exited_within_timeout -or $valRes.ntstatus_crash_name -ne "" -or $valRes.minidump_count -gt 0) {
            $HardFailure = $true
        } elseif ($valRes.exit_code -ne 0 -and -not ($IsHeadlessSession -and $valRes.headless_gl_unavailable)) {
            $HardFailure = $true
        }
    }

    $guiRes = Invoke-BoundedGClient -Label "bounded-gui-startup" -Arguments @(
        "--mute",
        "--width=1136",
        "--height=640",
        "--resources-dir=$ResDir",
        "--base-assets-dir=$ResDir",
        "--profile-dir=$ProfDir"
    )
    $Results += $guiRes
    if ($guiRes.ntstatus_crash_name -ne "" -or $guiRes.minidump_count -gt 0) {
        $HardFailure = $true
    }
} finally {
    Remove-Item -LiteralPath $SmokeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$AnyHeadlessGlLimit = @($Results | Where-Object { $_.headless_gl_unavailable }).Count -gt 0
$Report = [ordered]@{
    generated_at_utc             = (Get-Date).ToUniversalTime().ToString("o")
    executable                   = $ExePath
    session_id                   = $SessionId
    user_interactive             = $UserInteractive
    video_controllers            = $VideoControllers
    headless_ci_environment      = $IsHeadlessSession
    headless_wgl_limitation_hit  = $AnyHeadlessGlLimit
    gui_runtime_verdict          = if ($HardFailure) { "FAILED" } elseif ($AnyHeadlessGlLimit) { "HEADLESS_GL_UNAVAILABLE_DESKTOP_GPU_VERIFICATION_REQUIRED" } else { "PASSED" }
    runs                         = $Results
}

$Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
Write-Host "[SmokeTest] Verdict: $($Report.gui_runtime_verdict) | Report: $ReportPath"

if ($HardFailure) {
    Write-Host ($Report | ConvertTo-Json -Depth 6)
    Write-Error "Win32 smoke test detected a crash, minidump, hang, or unexpected non-zero exit!"
    exit 1
}
exit 0
