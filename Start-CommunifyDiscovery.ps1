#Requires -Version 2.0
<#
.SYNOPSIS
    Launcher for Invoke-CommunifyDiscovery.ps1. Parses and runs under Windows PowerShell 2.0.

.DESCRIPTION
    THIS SCRIPT IS READ-ONLY. It starts the discovery script and nothing else.

    Why it exists: the Exchange 2010 Management Shell shortcut starts
    "powershell.exe -version 2.0", and Windows Server 2008 R2 ships PowerShell 2.0. The
    discovery script needs Windows PowerShell 3.0 or later and refuses to load on a 2.0
    host, producing no files at all. This launcher is written so that PowerShell 2.0 can
    parse it, and it:

      1. finds Invoke-CommunifyDiscovery.ps1 in its own folder;
      2. if the current host is already PowerShell 3.0+ AND a 64-bit process, runs the
         discovery script in-process (so an Exchange Management Shell that is already loaded
         is reused);
      3. otherwise starts a fresh 64-bit powershell.exe WITHOUT a -Version pin, which gives
         the newest engine installed, and passes every parameter through;
      4. if no PowerShell 3.0+ engine is installed on this host at all, prints one
         instruction and exits with code 2.

    Exit codes: 0 = discovery ran (see its own output); 2 = no PowerShell 3.0+ engine on this
    host; 3 = Invoke-CommunifyDiscovery.ps1 not found next to this launcher.

.PARAMETER OutputPath
    Passed through to Invoke-CommunifyDiscovery.ps1.
.PARAMETER RedactHostnames
    Passed through.
.PARAMETER SkipNetworkTests
    Passed through.
.PARAMETER MessageTrackingDays
    Passed through (1-14).
.PARAMETER MaxMinutes
    Passed through (1-120, default 20).
.PARAMETER Quiet
    Passed through.
.PARAMETER CompactOutput
    Passed through (RMM mode).

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1

.EXAMPLE
    .\Start-CommunifyDiscovery.ps1 -OutputPath D:\Temp -RedactHostnames
    Run from any PowerShell window, including the Exchange Management Shell.

.NOTES
    Author  : BiTS Technology Group (bitsgroup.com.au)
    Version : 1.1.0
    Written for PowerShell 2.0 compatibility on purpose: no ordered dictionaries, no
    all-stream redirection, no containment operators introduced in 3.0, no automatic
    script-root variable, no static constructor calls, no scriptblock-to-delegate casts.
#>
param(
    [string]$OutputPath = '',
    [switch]$RedactHostnames,
    [switch]$SkipNetworkTests,
    [int]$MessageTrackingDays = 0,
    [int]$MaxMinutes = 0,
    [switch]$Quiet,
    [switch]$CompactOutput
)

$ErrorActionPreference = 'SilentlyContinue'
$launcherVersion = '1.1.0'
$targetName = 'Invoke-CommunifyDiscovery.ps1'

function Write-LauncherLine {
    param([string]$Text, [string]$Colour)
    if ($CompactOutput) { Write-Output ('launcher: ' + $Text); return }
    if ($Colour) { try { Write-Host $Text -ForegroundColor $Colour; return } catch { } }
    Write-Host $Text
}

# --- 1. Locate the discovery script next to this launcher --------------------------------
$here = $null
try { if ($MyInvocation.MyCommand.Path) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path } } catch { $here = $null }
if (-not $here) { $here = (Get-Location).Path }
$target = Join-Path $here $targetName
if (-not (Test-Path -LiteralPath $target)) {
    Write-LauncherLine ('[FAIL] ' + $targetName + ' was not found in ' + $here + '. Copy both files to the same folder and run again.') 'Red'
    exit 3
}

# --- 2. What are we running on? ------------------------------------------------------------
$hostMajor = 0
try { $hostMajor = [int]$PSVersionTable.PSVersion.Major } catch { $hostMajor = 0 }
$is64BitProcess = ([IntPtr]::Size -eq 8)
$is64BitOs = $is64BitProcess
if (-not $is64BitOs) { if ($env:PROCESSOR_ARCHITEW6432) { $is64BitOs = $true } }

# Newest installed Windows PowerShell engine (3.0, 4.0 or 5.1 register under ...\PowerShell\3).
$installedEngine = $null
try {
    $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -ErrorAction SilentlyContinue
    if ($key -and $key.PowerShellVersion) { $installedEngine = [string]$key.PowerShellVersion }
} catch { $installedEngine = $null }

$exe = $null
if ($is64BitOs -and -not $is64BitProcess) {
    # 32-bit process on 64-bit Windows (common under RMM agents): Sysnative reaches the 64-bit engine.
    $exe = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
}
else {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

# --- 3. Build the parameter set to pass through --------------------------------------------
$splat = @{}
$argList = @()
if ($OutputPath) { $splat['OutputPath'] = $OutputPath; $argList += '-OutputPath'; $argList += $OutputPath }
if ($RedactHostnames) { $splat['RedactHostnames'] = $true; $argList += '-RedactHostnames' }
if ($SkipNetworkTests) { $splat['SkipNetworkTests'] = $true; $argList += '-SkipNetworkTests' }
if ($MessageTrackingDays -gt 0) { $splat['MessageTrackingDays'] = $MessageTrackingDays; $argList += '-MessageTrackingDays'; $argList += [string]$MessageTrackingDays }
if ($MaxMinutes -gt 0) { $splat['MaxMinutes'] = $MaxMinutes; $argList += '-MaxMinutes'; $argList += [string]$MaxMinutes }
if ($Quiet) { $splat['Quiet'] = $true; $argList += '-Quiet' }
if ($CompactOutput) { $splat['CompactOutput'] = $true; $argList += '-CompactOutput' }

# --- 4. Run in-process when this host is already good enough --------------------------------
if ($hostMajor -ge 3 -and $is64BitProcess) {
    if (-not $CompactOutput) { Write-LauncherLine ('Start-CommunifyDiscovery ' + $launcherVersion + ': running ' + $targetName + ' in this PowerShell ' + $PSVersionTable.PSVersion + ' session.') 'Cyan' }
    & $target @splat
    exit $LASTEXITCODE
}

# --- 5. Otherwise re-launch the newest 64-bit engine without a -Version pin -----------------
if (-not $installedEngine) {
    Write-LauncherLine '[FAIL] This computer only has Windows PowerShell 2.0 (typical for Windows Server 2008 R2 without the Windows Management Framework 3.0+ update).' 'Red'
    Write-LauncherLine '       The discovery script needs PowerShell 3.0 or later. Please copy both files to any domain-joined Windows 10/11 or Windows Server 2016+ computer,' 'Yellow'
    Write-LauncherLine '       open Windows PowerShell as administrator there, and run Start-CommunifyDiscovery.ps1 from that computer.' 'Yellow'
    Write-LauncherLine '       It reads Exchange configuration from Active Directory and returns most of what is needed (AD-only mode).' 'Yellow'
    if ($CompactOutput) { Write-Output 'VERDICT=Launcher: no PowerShell 3.0+ engine on this host'; Write-Output 'TRUNCATION_GUARD=END_OF_OUTPUT' }
    exit 2
}
if (-not (Test-Path -LiteralPath $exe)) {
    Write-LauncherLine ('[FAIL] powershell.exe was not found at ' + $exe) 'Red'
    exit 2
}
$why = ''
if ($hostMajor -lt 3) { $why = 'this session is PowerShell ' + $hostMajor + '.x (the Exchange 2010 Management Shell pins -version 2.0)' }
elseif (-not $is64BitProcess) { $why = 'this session is a 32-bit process' }
if (-not $CompactOutput) { Write-LauncherLine ('Start-CommunifyDiscovery ' + $launcherVersion + ': ' + $why + '; starting 64-bit Windows PowerShell ' + $installedEngine + ' for ' + $targetName + '.') 'Cyan' }

$childArgs = @('-NoProfile', '-NoLogo', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $target) + $argList
& $exe $childArgs
$code = $LASTEXITCODE
if ($null -eq $code) { $code = 0 }
exit $code
