#Requires -Version 3.0
<#
.SYNOPSIS
    Read-only discovery of an on-premises Exchange management footprint, its hybrid
    configuration, Entra Connect, Active Directory and the automation that depends on it.

.DESCRIPTION
    THIS SCRIPT IS READ-ONLY. It makes no configuration changes to Exchange, Active
    Directory, Entra Connect, Windows or IIS. It creates nothing in the directory, changes
    no execution policy, installs nothing and connects to no cloud service.

    The only things it writes are its own output files, in a folder it creates under
    -OutputPath. The only optional outbound network activity is a handful of short TCP
    connection tests (no sign-in, no data sent), which -SkipNetworkTests turns off.

    BiTS Technology Group uses the output to decide between three designs for replacing
    the current Exchange management server: relocating it to an Azure VM, replacing it
    with the standalone Exchange Management Tools role, or moving recipient management
    entirely to Exchange Online. The output is deliberately limited to counts, versions,
    configuration and host sizing. It contains no mailbox names, addresses, group
    memberships, message content or credential values (see NOTES).

    Sections collected:
      A. Run metadata                     G. Entra Connect (ADConnect)
      B. Host / server sizing             H. Active Directory
      C. Exchange footprint               I. Automations (scheduled tasks, scripts)
      D. Non-recipient workloads (SMTP)   J. Network / Azure readiness
      E. Recipient inventory (counts)     K. Licensing posture signals
      F. Hybrid configuration             Summary and detected blockers

    The script works with or without the Exchange management tools installed, across
    Exchange 2010, 2013, 2016, 2019 and Subscription Edition. Without the tools it falls
    back to reading Exchange configuration directly from Active Directory.

    Run it through Start-CommunifyDiscovery.ps1 (the launcher in the same folder). The
    Exchange 2010 Management Shell shortcut pins powershell.exe to -version 2.0, on which
    this script cannot load; the launcher re-invokes the current Windows PowerShell engine
    (64-bit) and passes every parameter through.

    The run is bounded by -MaxMinutes (default 20). Sections that would start after the
    deadline are recorded as SKIPPED_DEADLINE, long enumerations stop early with a
    truncation flag, and discovery.json is rewritten after every section, so a run that
    is killed by an RMM timeout or Ctrl-C still leaves partial data on disk.

.PARAMETER OutputPath
    Parent folder for the output. A timestamped sub-folder named
    CommunifyDiscovery_<yyyyMMdd-HHmmss> is created beneath it.
    Default: the current user's Desktop. When that does not exist or is not writable
    (for example when run as SYSTEM by an RMM agent) the script falls back to
    %ProgramData%\CommunifyDiscovery, then to %TEMP%.

.PARAMETER MaxMinutes
    Global deadline for collection, in minutes (1-120, default 20). Sections not started
    by the deadline are skipped and marked SKIPPED_DEADLINE; the summary and the output
    files are always written.

.PARAMETER CompactOutput
    RMM mode. Changes only what is written to the console, never what is collected or
    written to the output files. Suppresses the banner and per-section progress and
    instead prints a short machine-readable block of key=value lines (kept under 8 KB),
    one status line per section, a VERDICT line and a final
    TRUNCATION_GUARD=END_OF_OUTPUT sentinel. Intended for tools that capture stdout and
    truncate it (NinjaOne truncates at roughly 10 KB).

.PARAMETER RedactHostnames
    Hardened mode. Also replaces server hostnames, domain and forest names, accepted
    domains and URL hostnames with stable one-way hashes (id:xxxxxxxxxxxx). Off by default
    because those values are organisation data, not personal data, and are needed for
    the design.

.PARAMETER SkipNetworkTests
    Skips the TCP connectivity tests to the domain controller and to a small fixed list of
    Microsoft endpoints, and the latency/MTU checks.

.PARAMETER MessageTrackingDays
    How many days of message tracking log to summarise (aggregate counts only).
    Default 7, maximum 14.

.PARAMETER Quiet
    Suppresses per-section progress on the console. Failures and the closing message are
    still shown.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CommunifyDiscovery.ps1
    Runs with defaults and writes to the Desktop.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CommunifyDiscovery.ps1 -OutputPath D:\Temp -RedactHostnames
    Writes to D:\Temp\CommunifyDiscovery_<stamp> with hostnames and domain names hashed.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CommunifyDiscovery.ps1 -SkipNetworkTests -MessageTrackingDays 14

.NOTES
    Author   : BiTS Technology Group (bitsgroup.com.au)
    Version  : 1.1.0
    Requires : Windows PowerShell 3.0 or later (designed and tested against 5.1).
               PowerShell 7 is not required. Use Start-CommunifyDiscovery.ps1 to launch.

    THIS SCRIPT IS READ-ONLY.
    Audit note for reviewers. Every data-collecting call is a Get-*, Test-*, registry read,
    WMI/CIM read, event-log read, file-metadata read or ADSI read. The non-Get verbs that
    appear in this file, and why:
      New-Object          instantiates in-memory .NET/COM objects only (DirectorySearcher,
                          TcpClient, Stopwatch, Schedule.Service, RNG). Nothing is created
                          in AD, Exchange or on disk.
      Add-PSSnapin        loads Exchange cmdlets into THIS PowerShell session only.
      Import-Module       loads modules (ADSync, WebAdministration, ServerManager) or an
      Import-PSSession    implicit Exchange remoting session into THIS PowerShell session
      New-PSSession       only.
      Remove-PSSession    closes that implicit remoting session at the end of the run so
                          that it does not hold an Exchange throttling slot.
      Set-ADServerSettings -ViewEntireForest $true
                          changes only the recipient scope of THIS PowerShell session so
                          that recipient counts cover the whole forest. It writes nothing.
      [System.IO.File]::WriteAllText / Compress-Archive
                          write the output files and optional zip into the output folder.
    No other Set-/New-/Remove-/Enable-/Disable-/Add-/Install- cmdlet is invoked.
    Verb-Noun strings that look like other cmdlets appear only inside regular expressions
    and lists used to fingerprint the client's own scripts; they are never executed.

    Privacy. The script never collects mailbox names, display names, UPNs, e-mail addresses,
    group memberships, user lists, message subjects or bodies, sender/recipient addresses,
    file contents, credential values, private keys or full certificate thumbprints.
    Account names that must be recorded (service and scheduled-task run-as accounts) are
    replaced by Protect-Identifier: SHA-256 over a 32-byte random salt generated for this
    run plus the value, truncated to 12 hex characters (id:xxxxxxxxxxxx). The salt is never
    written anywhere, so the hash allows correlation within one report but cannot be
    reversed by dictionary attack, and it differs between runs. Exception messages are
    never emitted; they are reduced to a classified reason code plus the same kind of hash.
    Scheduled-task names, task paths, task arguments and script file names are reduced to
    hashes, lengths, folder depth, whitelisted keywords and cmdlet names.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = '',

    [Parameter()]
    [switch]$RedactHostnames,

    [Parameter()]
    [switch]$SkipNetworkTests,

    [Parameter()]
    [ValidateRange(1, 14)]
    [int]$MessageTrackingDays = 7,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$MaxMinutes = 20,

    [Parameter()]
    [switch]$Quiet,

    [Parameter()]
    [switch]$CompactOutput
)

# ---------------------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------------------
# Non-terminating errors are swallowed: every collection call that matters uses
# -ErrorAction Stop inside try/catch and records its own warning. Anything else written
# to the error stream would land on stderr, which RMM tools (NinjaOne included) treat as
# job failure, and would bury the compact-output sentinel.
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$script:ScriptVersion   = '1.1.5'
$script:StartUtc        = [DateTime]::UtcNow
$script:StartLocal      = Get-Date
$script:Redact          = [bool]$RedactHostnames
$script:Compact         = [bool]$CompactOutput
$script:Quiet           = ([bool]$Quiet -or $script:Compact)
$script:SkipNet         = [bool]$SkipNetworkTests
$script:TrackingDays    = $MessageTrackingDays
$script:MaxMinutes      = $MaxMinutes
$script:DeadlineUtc     = $script:StartUtc.AddMinutes($MaxMinutes)
$script:DeadlineHit     = $false
$script:DeadlineMarker  = 'COMMUNIFY_DEADLINE_REACHED'
$script:RunCompleted    = $false
$script:ExchangeSession = $null   # implicit remoting session, removed at the end of the run

# Per-run salt for Protect-Identifier. 32 random bytes, held in memory only, never written
# to any output. Hashes therefore correlate within a report but cannot be dictionary-reversed
# and differ from run to run.
$script:HashSalt = New-Object byte[] 32
try {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($script:HashSalt)
    $rng.Dispose()
}
catch {
    # Fallback (never expected): derive from a GUID and the clock so the salt is still unpredictable.
    $seed = [System.Text.Encoding]::UTF8.GetBytes([Guid]::NewGuid().ToString() + [DateTime]::UtcNow.Ticks)
    $sha = [System.Security.Cryptography.SHA256]::Create(); $script:HashSalt = $sha.ComputeHash($seed); $sha.Dispose()
}

# Colour support: some non-interactive hosts expose no RawUI and reject colour parameters.
$script:ColourSupported = $false
try {
    if ($null -ne $Host -and $null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
        $null = $Host.UI.RawUI.ForegroundColor
        $script:ColourSupported = $true
    }
}
catch { $script:ColourSupported = $false }
$script:Sections        = [ordered]@{}   # section key -> collected data
$script:SectionMeta     = [ordered]@{}   # section key -> status/timing/warnings
$script:FailedSections  = New-Object System.Collections.Generic.List[string]
$script:CurrentWarnings = $null
$script:Report          = New-Object System.Collections.Generic.List[string]

# Shared context populated as sections run (host name, domain, Exchange install info...)
$script:Ctx = @{
    ComputerName        = $env:COMPUTERNAME
    IsDomainJoined      = $false
    DomainFqdn          = $null
    ForestFqdn          = $null
    ConfigNC            = $null
    RootDomainNC        = $null
    ExchangeInstalled   = $false
    ExchangeInstallPath = $null
    ExchangeVersionKey  = $null          # 'v14' or 'v15'
    ExchangeProduct     = $null          # friendly name
    ExchangeToolsLoaded = $false
    ExchangeToolsMethod = 'None'
    ExchangeToolsMode   = 'None'         # Full | RecipientManagementOnly | None
    DcHostname          = $null
}

# ---------------------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------------------
function Write-ConsoleLine {
    # Console-only text. Colour is used when the host supports it; otherwise the same
    # text is written without colour. Nothing here is emitted to the pipeline, so
    # calling it inside a collection function cannot pollute that function's return value.
    param([string]$Text, [string]$Colour = 'Gray')
    if ($script:ColourSupported) {
        try { Write-Host $Text -ForegroundColor $Colour; return } catch { }
    }
    try { Write-Host $Text }
    catch { try { [Console]::Out.WriteLine($Text) } catch { } }
}

function Write-Status {
    param(
        [ValidateSet('INFO', 'OK', 'WARN', 'FAIL', 'HEAD', 'SKIP')]
        [string]$Level,
        [string]$Message
    )
    if ($script:Compact) { return }   # compact mode reports section status in its own block
    if ($script:Quiet -and $Level -in @('INFO', 'OK', 'HEAD')) { return }
    $colour = switch ($Level) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'SKIP' { 'Yellow' }
        'HEAD' { 'Cyan' }
        default { 'Gray' }
    }
    $prefix = if ($Level -eq 'HEAD') { '' } else { ('[{0,-4}] ' -f $Level) }
    Write-ConsoleLine -Text ($prefix + $Message) -Colour $colour
}

function Write-SectionWarning {
    # Records a non-fatal problem against the section currently being collected.
    param([string]$Message)
    $clean = Protect-Text -Text $Message
    if ($null -ne $script:CurrentWarnings) { [void]$script:CurrentWarnings.Add($clean) }
    Write-Status -Level 'WARN' -Message $clean
}

# ---------------------------------------------------------------------------------------
# Deadline helpers
# ---------------------------------------------------------------------------------------
function Test-PastDeadline {
    # True once the -MaxMinutes budget is spent. Sections check it before starting; long
    # enumerations check it periodically and stop with a truncation flag.
    if ([DateTime]::UtcNow -ge $script:DeadlineUtc) { $script:DeadlineHit = $true; return $true }
    return $false
}

function Assert-Deadline {
    # Used inside ForEach-Object pipelines, where 'break' would exit the wrong scope: throwing
    # the marker stops the upstream cmdlet; the caller catches it and records truncation.
    if (Test-PastDeadline) { throw $script:DeadlineMarker }
}

function Test-DeadlineException {
    param($ErrorRecord)
    try { return ("$($ErrorRecord.Exception.Message)" -eq $script:DeadlineMarker) } catch { return $false }
}

# ---------------------------------------------------------------------------------------
# Privacy helpers
# ---------------------------------------------------------------------------------------
function Protect-Identifier {
    # One-way pseudonym: 'id:' + first 12 hex characters of SHA-256(salt + lower-cased value).
    # The salt is 32 random bytes generated for this run and never written to output, so the
    # same account/name correlates within the report but cannot be recovered from a wordlist.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $sha = $null
    try {
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.Trim().ToLowerInvariant())
        [void]$sha.TransformBlock($script:HashSalt, 0, $script:HashSalt.Length, $null, 0)
        [void]$sha.TransformFinalBlock($bytes, 0, $bytes.Length)
        $hash  = $sha.Hash
        return ('id:' + [BitConverter]::ToString($hash, 0, 6).Replace('-', '').ToLowerInvariant())
    }
    catch { return 'id:hash-failed' }
    finally { if ($null -ne $sha) { $sha.Dispose() } }
}

function ConvertTo-SafeError {
    # Reduces an exception to a classified reason code, the .NET exception type and a salted
    # hash of the message. The raw message is never emitted: Exchange and AD error text
    # routinely carries distinguished names, canonical names, legacy Exchange DNs and
    # single-label UPNs that no regex scrub reliably catches. Nothing downstream needs more
    # than the reason code.
    param($ErrorRecord)
    $msg = ''; $type = ''
    try {
        $ex = $null
        if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
        elseif ($ErrorRecord -is [Exception]) { $ex = $ErrorRecord }
        # PowerShell wraps .NET method failures (MethodInvocationException) and -ErrorAction Stop
        # failures (ActionPreferenceStopException); the inner exception carries the real reason.
        $hops = 0
        while ($null -ne $ex -and $null -ne $ex.InnerException -and $hops -lt 3 -and ($ex.GetType().Name -in @('MethodInvocationException', 'ActionPreferenceStopException', 'TargetInvocationException', 'AggregateException', 'CmdletInvocationException'))) { $ex = $ex.InnerException; $hops++ }
        if ($null -ne $ex) { $msg = "$($ex.Message)"; $type = $ex.GetType().Name }
        if (-not $msg -and $ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $msg = "$($ErrorRecord.FullyQualifiedErrorId)" }
        if (-not $msg -and -not $type) { $msg = "$ErrorRecord" }
    }
    catch { $msg = '' }
    if ($msg -eq $script:DeadlineMarker) { return 'Deadline' }
    $reason = 'Other'
    if ($type -eq 'CommandNotFoundException' -or $msg -match '(?i)not recognized as the name of a cmdlet|is not recognized as a cmdlet|CommandNotFound') { $reason = 'CmdletMissing' }
    elseif ($type -eq 'UnauthorizedAccessException' -or $msg -match '(?i)access(-| )?denied|access is denied|unauthori[sz]ed|not authorized|insufficient (access|rights|permission)|permission|forbidden|0x80070005|E_ACCESSDENIED|logon failure|isn''t assigned to any management role|not assigned any management role') { $reason = 'AccessDenied' }
    elseif ($type -eq 'OutOfMemoryException' -or $msg -match '(?i)out of memory|OutOfMemory') { $reason = 'OutOfMemory' }
    elseif ($type -eq 'TimeoutException' -or $msg -match '(?i)\btime(d)?[ -]?out\b|timeout|time limit') { $reason = 'Timeout' }
    elseif ($msg -match '(?i)couldn''t be found|could not be found|cannot find|not found|does not exist|doesn''t exist|no such|not present|no longer exists') { $reason = 'NotFound' }
    elseif ($msg -match '(?i)RPC server|network path|server is not operational|unable to connect|could not connect|connection|WinRM|remote server|not reachable|unreachable|refused|DNS name|no logon servers|target principal name|Kerberos|SSL/TLS|The request was aborted') { $reason = 'ConnectivityOrRpc' }
    elseif ($msg -match '(?i)parameter|cannot bind|cannot validate|not valid|invalid|cannot convert|cannot process argument|is not supported') { $reason = 'ParameterOrFormat' }
    elseif ($msg -match '(?i)WMI|CIM|Invalid class|Provider load failure|0x8004100') { $reason = 'WmiOrCim' }
    $hash = Protect-Identifier -Value $msg
    if (-not $hash) { $hash = 'id:empty' }
    if ($type) { return ('{0} ({1}) msg:{2}' -f $reason, $type, $hash.Substring(3)) }
    return ('{0} msg:{1}' -f $reason, $hash.Substring(3))
}

function Protect-Hostname {
    # Hostnames / domain names are organisation data and stay in clear unless -RedactHostnames.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($script:Redact) { return (Protect-Identifier -Value $Value) }
    return $Value
}

function Protect-HostnameList {
    param($Values)
    $out = @()
    foreach ($v in @($Values)) { if ($null -ne $v -and "$v" -ne '') { $out += (Protect-Hostname -Value "$v") } }
    return ,$out
}

function Protect-Url {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if (-not $script:Redact) { return $Value }
    try {
        $uri = [Uri]$Value
        if ($uri.IsAbsoluteUri) {
            return ('{0}://{1}{2}' -f $uri.Scheme, (Protect-Identifier -Value $uri.Host), $uri.PathAndQuery)
        }
    }
    catch { }
    return (Protect-Identifier -Value $Value)
}

function Protect-UrlList {
    param($Values)
    $out = @()
    foreach ($v in @($Values)) { if ($null -ne $v -and "$v" -ne '') { $out += (Protect-Url -Value "$v") } }
    return ,$out
}

$script:WellKnownAccounts = @('SYSTEM', 'LOCALSYSTEM', 'LOCAL SERVICE', 'LOCALSERVICE', 'NETWORK SERVICE',
    'NETWORKSERVICE', 'ANONYMOUS LOGON', 'EVERYONE', 'AUTHENTICATED USERS', 'ADMINISTRATORS', 'USERS',
    'IUSR', 'DEFAULTAPPPOOL', 'MSEXCHANGEAPPPOOL', 'ADMINISTRATOR', 'INTERACTIVE', 'SERVICE')
$script:WellKnownAuthorities = @('NT AUTHORITY', 'AUTHORITY', 'NT SERVICE', 'SERVICE', 'BUILTIN', 'IIS APPPOOL',
    'APPPOOL', 'NT VIRTUAL MACHINE', 'WORKGROUP', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20')

function Protect-Account {
    # Keeps well-known principals (LocalSystem, NT AUTHORITY\..., IIS APPPOOL\...) in clear,
    # keeps the domain part (organisation data), hashes the account part.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    $upper = $v.ToUpperInvariant()
    if ($upper -in $script:WellKnownAccounts) { return $v }
    if ($upper -match '^(NT AUTHORITY|NT SERVICE|BUILTIN|IIS APPPOOL|NT VIRTUAL MACHINE)\\') { return $v }
    if ($upper -match '^S-1-5-(18|19|20)$') { return $v }
    if ($v -match '^(?<dom>[^\\@]+)\\(?<acct>.+)$') {
        $dom  = $Matches['dom']
        $acct = $Matches['acct']
        if ($acct.ToUpperInvariant() -in $script:WellKnownAccounts) { return $v }
        if ($dom -eq '.' ) { return ('.\' + (Protect-Identifier -Value $acct)) }
        return ((Protect-Hostname -Value $dom) + '\' + (Protect-Identifier -Value $acct))
    }
    if ($v -match '^(?<acct>[^@]+)@(?<dom>.+)$') {
        return ((Protect-Identifier -Value $Matches['acct']) + '@' + (Protect-Hostname -Value $Matches['dom']))
    }
    return (Protect-Identifier -Value $v)
}

function Protect-Path {
    # Regex form for free text: hashes the user-name segment of ...\Users\<name>\... wherever
    # it appears. For a value that is known to be a path use Protect-FilePath, which is
    # stricter (every non-generic folder segment and every file name is hashed).
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            return ($m.Groups[1].Value + (Protect-Identifier -Value $m.Groups[2].Value))
        }
        return [regex]::Replace($Value, '(?i)([\\/]Users[\\/])([^\\/]+)', $evaluator)
    }
    catch { return '<path-redaction-failed>' }
}

# Folder names that carry no personal data and are kept in clear inside paths. Every other
# folder segment, and every file name, is replaced by a salted hash (extension kept).
$script:GenericPathSegments = @('windows', 'system32', 'syswow64', 'sysnative', 'program files', 'program files (x86)', 'programdata',
    'users', 'public', 'default', 'desktop', 'documents', 'downloads', 'appdata', 'local', 'roaming', 'temp', 'tmp',
    'inetpub', 'wwwroot', 'logs', 'logfiles', 'log', 'logging', 'scripts', 'script', 'automation', 'tasks', 'task', 'jobs',
    'job', 'tools', 'admin', 'ps', 'powershell', 'windowspowershell', 'v1.0', 'modules', 'batch', 'util', 'utils',
    'utilities', 'microsoft', 'microsoft shared', 'common files', 'exchange server', 'exchange', 'exchsrvr', 'v14', 'v15',
    'bin', 'clientaccess', 'frontend', 'backend', 'owa', 'ecp', 'ews', 'oab', 'mapi', 'rpc', 'autodiscover', 'powershell-proxy',
    'cmdletinfra', 'httpproxy', 'transportroles', 'mailbox', 'data', 'backup', 'backups', 'export', 'exports', 'import',
    'imports', 'reports', 'report', 'config', 'configuration', 'apps', 'app', 'web', 'www', 'sites', 'site', 'sync',
    'microsoft azure ad sync', 'azure ad connect', 'azure ad sync', 'microsoft azure active directory connect', 'entra connect',
    'iis', 'wsus', 'sql', 'mssql', 'veeam', 'system', 'tasks', 'ninja', 'ninjarmm', 'ninjarmmagent', 'datto', 'kaseya',
    'connectwise', 'labtech', 'n-able', 'atera', 'agent', 'agents', 'prefetch', 'start menu', 'programs', 'startup',
    'communifydiscovery', 'bits', 'it', 'ict', 'shared', 'share', 'shares', 'home', 'homes', 'homedirs', 'profiles',
    'redirected', 'redirectedfolders', 'archive', 'archives', 'old', 'new', 'test', 'prod', 'production', 'dev')

$script:GenericExecutables = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe',
    'robocopy.exe', 'xcopy.exe', 'schtasks.exe', 'msiexec.exe', 'rundll32.exe', 'wmic.exe', 'net.exe', 'net1.exe',
    'wbadmin.exe', 'vssadmin.exe', 'ntbackup.exe', 'sc.exe', 'reg.exe', 'regsvr32.exe', 'certutil.exe', 'dsquery.exe',
    'dsget.exe', 'ldifde.exe', 'csvde.exe', 'repadmin.exe', 'dfsrdiag.exe', 'gpupdate.exe', 'shutdown.exe', 'taskkill.exe',
    'forfiles.exe', 'bitsadmin.exe', 'curl.exe', 'wget.exe', 'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe',
    'perl.exe', 'php.exe', 'ruby.exe', 'sqlcmd.exe', 'bcp.exe', 'exsetup.exe', 'setup.exe', 'update.exe', 'updater.exe',
    'agent.exe', 'ninjarmmagent.exe', 'labtech.exe', 'ltsvc.exe', 'kaseya.exe', 'agentmon.exe', 'veeam.backup.manager.exe',
    'msedge.exe', 'chrome.exe', 'iexplore.exe', 'explorer.exe', 'notepad.exe', 'mmc.exe', 'dfsfrsdiag.exe', 'defrag.exe',
    'compattelrunner.exe', 'dism.exe', 'wuauclt.exe', 'usoclient.exe', 'sdclt.exe', 'sfc.exe', 'chkdsk.exe', 'diskpart.exe')

function Protect-FilePath {
    # Structured path redaction. Keeps the drive or UNC server (server through Protect-Hostname),
    # keeps folder segments that are generic (see GenericPathSegments) or version-like, hashes
    # every other folder segment, and hashes the file name while keeping its extension.
    # Example: D:\HomeDirs\jsmith\Offboard-JaneSmith.ps1 -> D:\HomeDirs\id:1a2b3c4d5e6f\id:0f9e8d7c6b5a.ps1
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        $v = $Value.Trim().Trim('"').Trim("'")
        if ($v.Length -gt 400) { $v = $v.Substring(0, 400) }
        $prefix = ''
        $rest = $v
        if ($v -match '^(?<d>[A-Za-z]:)(?<r>[\\/].*)?$') { $prefix = $Matches['d'].ToUpperInvariant() + '\'; $rest = "$($Matches['r'])" }
        elseif ($v -match '^\\\\(?<srv>[^\\/]+)(?<r>[\\/].*)?$') { $prefix = '\\' + (Protect-Hostname -Value $Matches['srv']) + '\'; $rest = "$($Matches['r'])" }
        elseif ($v -match '^(?<env>%[^%]+%)(?<r>[\\/].*)?$') { $prefix = $Matches['env'] + '\'; $rest = "$($Matches['r'])" }
        $segments = @($rest.Trim('\', '/') -split '[\\/]+' | Where-Object { $_ -ne '' })
        if ($segments.Count -eq 0) { return $prefix.TrimEnd('\') + $(if ($prefix) { '\' } else { '' }) }
        $outSegs = @()
        for ($i = 0; $i -lt $segments.Count; $i++) {
            $seg = $segments[$i]
            $isLast = ($i -eq $segments.Count - 1)
            $lower = $seg.ToLowerInvariant()
            $hasExt = ($isLast -and $seg -match '^(?<base>.+)(?<ext>\.[A-Za-z0-9]{1,5})$')
            if ($hasExt) {
                $ext = $Matches['ext'].ToLowerInvariant()
                if ($script:GenericExecutables -contains $lower) { $outSegs += $seg }
                else { $outSegs += ((Protect-Identifier -Value $Matches['base']) + $ext) }
            }
            elseif ($script:GenericPathSegments -contains $lower) { $outSegs += $seg }
            elseif ($lower -match '^v?\d+(\.\d+)*$' -or $lower -match '^\$') { $outSegs += $seg }
            elseif ($lower -match '^[a-z0-9]{1,2}$') { $outSegs += $seg }   # single letters / two-char tags
            else { $outSegs += (Protect-Identifier -Value $seg) }
        }
        return ($prefix + ($outSegs -join '\'))
    }
    catch { return '<path-redaction-failed>' }
}

$script:HintVerbs = @('get', 'set', 'new', 'remove', 'enable', 'disable', 'add', 'update', 'start', 'stop', 'restart', 'sync', 'export', 'import',
    'create', 'delete', 'onboard', 'offboard', 'provision', 'deprovision', 'check', 'test', 'report', 'send', 'move', 'copy', 'backup', 'restore',
    'cleanup', 'clean', 'purge', 'run', 'invoke', 'process', 'reset', 'rename', 'convert', 'audit', 'monitor', 'notify', 'archive', 'migrate',
    'assign', 'grant', 'revoke', 'block', 'unblock', 'lock', 'unlock', 'install', 'uninstall', 'deploy', 'build', 'generate', 'fix', 'repair',
    'verify', 'validate', 'find', 'search', 'list', 'show', 'write', 'read', 'load', 'save', 'push', 'pull', 'fetch', 'refresh', 'rotate',
    'schedule', 'compress', 'expand', 'mount', 'dismount', 'join', 'leave', 'register', 'unregister', 'publish', 'watch', 'wait', 'terminate',
    'retire', 'decommission', 'setup', 'configure', 'apply', 'merge', 'split', 'compare', 'count', 'measure', 'ping', 'trace', 'log', 'email',
    'mail', 'daily', 'weekly', 'monthly', 'nightly', 'hourly', 'auto', 'batch', 'bulk', 'mass', 'hr', 'payroll', 'ad', 'aad', 'exo', 'exchange',
    'o365', 'm365', 'entra', 'azure', 'user', 'users', 'mailbox', 'mailboxes', 'group', 'groups', 'license', 'licence', 'sync', 'hybrid',
    'leaver', 'leavers', 'joiner', 'joiners', 'starter', 'starters', 'mover', 'movers', 'termination', 'terminate', 'new-user', 'newuser')

function Get-FileNameHint {
    # 'Offboard-JaneSmith.ps1' -> 'Offboard-*.ps1'; 'sync_users.ps1' -> 'sync_*.ps1'. Only a
    # whitelisted purpose verb is kept as the prefix; anything else ('JaneSmith-Offboard.ps1')
    # becomes '*.ps1', so a person's name can never survive as the "verb".
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $leaf = [System.IO.Path]::GetFileName($Path)
        $ext  = [System.IO.Path]::GetExtension($leaf).ToLowerInvariant()
        $base = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
        if ($base -match '^(?<verb>[A-Za-z0-9]{2,12})(?<sep>[-_ ]|$)' -and $script:HintVerbs -contains $Matches['verb'].ToLowerInvariant()) {
            $sep = $Matches['sep']; if (-not $sep) { $sep = '' }
            return ($Matches['verb'] + $sep + '*' + $ext)
        }
        return ('*' + $ext)
    }
    catch { return $null }
}

$script:PurposeKeywords = @('onboard', 'onboarding', 'offboard', 'offboarding', 'joiner', 'leaver', 'mover', 'starter', 'new user',
    'new starter', 'terminate', 'termination', 'disable', 'enable', 'create', 'remove', 'delete', 'cleanup', 'clean up', 'archive',
    'mailbox', 'mailboxes', 'remote mailbox', 'shared mailbox', 'contact', 'contacts', 'distribution', 'group', 'groups', 'membership',
    'license', 'licence', 'licensing', 'exchange', 'entra', 'azure', 'aad', 'ad sync', 'adsync', 'dirsync', 'sync', 'hybrid',
    'migration', 'migrate', 'active directory', 'ad ', 'ldap', 'user', 'users', 'account', 'accounts', 'password', 'expiry',
    'report', 'reporting', 'audit', 'backup', 'export', 'import', 'csv', 'hr', 'payroll', 'teams', 'sharepoint', 'onedrive',
    'intune', 'm365', 'o365', 'office 365', 'graph', 'msol', 'exchange online', 'eol', 'exo', 'smtp', 'relay', 'mail',
    'email', 'e-mail', 'signature', 'calendar', 'room', 'resource', 'ooo', 'out of office', 'forward', 'forwarding', 'alias',
    'proxy address', 'gal', 'address list', 'public folder', 'transport', 'queue', 'certificate', 'renew', 'monitor',
    'health', 'alert', 'notify', 'notification', 'log', 'logs', 'purge', 'retention', 'quota', 'cleanup', 'maintenance',
    'reboot', 'restart', 'service', 'iis', 'sql', 'database', 'dag', 'replication', 'dfs', 'gpo', 'group policy', 'printer',
    'file share', 'home drive', 'home folder', 'profile', 'wsus', 'update', 'patch', 'rmm', 'ninja', 'datto', 'kaseya')

function Get-PurposeKeywords {
    # Returns the whitelisted purpose keywords present in a free-text value (task names,
    # descriptions). The text itself is never emitted.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    $found = @()
    try {
        $t = ' ' + $Text.ToLowerInvariant() + ' '
        foreach ($k in $script:PurposeKeywords) { if ($t.Contains($k)) { $found += $k.Trim() } }
    }
    catch { }
    return ,@($found | Select-Object -Unique | Sort-Object)
}

function Protect-Text {
    # Scrubs free text (error messages, command lines): e-mail addresses, DOMAIN\account
    # tokens, obvious password/secret arguments and user profile paths.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    try {
        # password / secret style arguments: -Password xxx, /p:xxx, password=xxx, -ClientSecret xxx
        $t = [regex]::Replace($t, '(?i)((?:^|[\s"''])(?:-|--|/)(?:password|pass|pwd|p|secret|clientsecret|token|apikey|key|credential)\s*[:=\s]\s*)("[^"]*"|''[^'']*''|\S+)', '$1<redacted>')
        $t = [regex]::Replace($t, '(?i)\b((?:password|passwd|pwd|secret|clientsecret|token|apikey)\s*[:=]\s*)("[^"]*"|''[^'']*''|\S+)', '$1<redacted>')
        # e-mail addresses / UPNs
        $emailEval = [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            return ('<email:' + (Protect-Identifier -Value $m.Value) + '>')
        }
        $t = [regex]::Replace($t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+', $emailEval)
        # DOMAIN\account (not preceded by a backslash, colon or word character, so file paths are left alone)
        $acctEval = [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            return (Protect-Account -Value $m.Value)
        }
        $t = [regex]::Replace($t, '(?<![\\:\w./])([A-Za-z][A-Za-z0-9-]{1,15})\\([A-Za-z0-9._$-]{2,})', $acctEval)
        $t = Protect-Path -Value $t
        if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + '...' }
    }
    catch { return '<text-redaction-failed>' }
    return $t
}

# ---------------------------------------------------------------------------------------
# Value / object helpers
# ---------------------------------------------------------------------------------------
function ConvertTo-IsoString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $d = [DateTime]$Value
        if ($d.Year -lt 1990) { return $null }   # COM "never" dates (1899-12-30) and the like
        return $d.ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
    catch { return "$Value" }
}

function ConvertTo-SafeValue {
    # Reduces any value to JSON-friendly primitives: strings, numbers, booleans, arrays of strings.
    # Depth-capped: a live .NET/COM object with a Parent/Children cycle would otherwise recurse
    # until the process dies with an uncatchable StackOverflowException.
    param($Value, [int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Depth -gt 20) { return '<max depth>' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [DateTime]) { return (ConvertTo-IsoString -Value $Value) }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or
        $Value -is [decimal] -or $Value -is [int16] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [byte]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $d = [ordered]@{}
        foreach ($k in $Value.Keys) { $d["$k"] = ConvertTo-SafeValue -Value $Value[$k] -Depth ($Depth + 1) }
        return $d
    }
    # Only enumerate collection types WE built. Enumerating an arbitrary live .NET object (an ADSI
    # property collection, a certificate store, a WMI instance) expands its whole property graph:
    # that bloated discovery.json from ~50 KB of real data to 1.16 MB on King Springs, and is a
    # privacy risk as well, since an unvetted object can carry identity data past the field-by-field
    # redaction. Anything else is reduced to its ToString().
    if ($Value -is [array] -or $Value -is [System.Collections.ArrayList] -or
        $Value -is [System.Collections.Generic.List[object]] -or $Value -is [System.Collections.Generic.List[string]]) {
        $arr = @()
        foreach ($i in $Value) {
            if ($null -eq $i) { continue }
            if ($i -is [System.Collections.IDictionary]) { $arr += ,(ConvertTo-SafeValue -Value $i -Depth ($Depth + 1)) }
            else { $arr += "$i" }
        }
        return ,$arr
    }
    try { return "$Value" } catch { return '<unconvertible>' }
}

function Select-SafeProperties {
    # Projects an object onto an explicit whitelist of properties (missing properties are
    # silently skipped, which is how version differences between Exchange releases are
    # absorbed). Hostname/URL properties are passed through the privacy helpers.
    param(
        $InputObject,
        [string[]]$Properties,
        [string[]]$HostnameProperties = @(),
        [string[]]$UrlProperties = @(),
        [string[]]$AccountProperties = @(),
        [string[]]$PathProperties = @()
    )
    $o = [ordered]@{}
    if ($null -eq $InputObject) { return $o }
    foreach ($p in $Properties) {
        $prop = $InputObject.PSObject.Properties[$p]
        if ($null -eq $prop) { continue }
        $v = $null
        try { $v = ConvertTo-SafeValue -Value $prop.Value } catch { $v = '<unreadable>' }
        if ($null -ne $v) {
            if ($HostnameProperties -contains $p) {
                if ($v -is [array]) { $v = Protect-HostnameList -Values $v } else { $v = Protect-Hostname -Value "$v" }
            }
            elseif ($UrlProperties -contains $p) {
                if ($v -is [array]) { $v = Protect-UrlList -Values $v } else { $v = Protect-Url -Value "$v" }
            }
            elseif ($AccountProperties -contains $p) {
                if ($v -is [array]) { $v = @(foreach ($x in $v) { Protect-Account -Value "$x" }) } else { $v = Protect-Account -Value "$v" }
            }
            elseif ($PathProperties -contains $p) {
                if ($v -is [array]) { $v = @(foreach ($x in $v) { Protect-FilePath -Value "$x" }) } else { $v = Protect-FilePath -Value "$v" }
            }
        }
        $o[$p] = $v
    }
    return $o
}

function Get-PropertySafe {
    param($InputObject, [string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function Get-SafeCount {
    # Element count that is 0 for $null and for the string markers ('cmdlet not available')
    # this script stores in place of collections. @($null).Count is 1 and @('text').Count is 1,
    # which inflated eight reported counts and produced phantom findings (a "remote public
    # folder mailbox" on every Exchange 2010 org, for one).
    param($Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [string]) { return 0 }
    if ($Value -is [System.Collections.IDictionary]) { return 1 }
    if ($Value -is [System.Collections.IEnumerable]) { $n = 0; foreach ($i in $Value) { if ($null -ne $i) { $n++ } }; return $n }
    return 1
}

function Get-CmdletUnavailableNote {
    # Finding 39: under the snap-in path Get-Command sees every cmdlet regardless of RBAC; under
    # implicit remoting only cmdlets the operator's roles allow are imported. So "cmdlet not
    # available" usually means permissions, not version, and the note says so.
    param([string]$Cmdlet)
    $method = "$($script:Ctx.ExchangeToolsMethod)"
    $known = "$($script:Ctx.ExchangeProduct)"
    if (-not $script:Ctx.ExchangeToolsLoaded) { return ('{0} not available: no Exchange cmdlets loaded in this session' -f $Cmdlet) }
    if ($method -match 'remoting|RemoteExchange|Pre-loaded') { return ('{0} not available in this session (load method: {1}). Under remoting only RBAC-authorised cmdlets are imported, so this most likely reflects the operator''s roles, not the Exchange version{2}.' -f $Cmdlet, $method, $(if ($known) { " ($known)" } else { '' })) }
    return ('{0} not available in this session (load method: {1}); the cmdlet does not exist in this Exchange version{2} or tools mode.' -f $Cmdlet, $method, $(if ($known) { " ($known)" } else { '' }))
}

function Get-RegistryValue {
    # Read-only registry access. Returns $null when the key or value does not exist.
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Get-RegistryKeyNames {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return ,@() }
        return ,@(Get-ChildItem -LiteralPath $Path -ErrorAction Stop | ForEach-Object { $_.PSChildName })
    }
    catch { return ,@() }
}

function Get-CimSafe {
    # CIM first, WMI fallback (older hosts). Returns an array (possibly empty).
    param([string]$Class, [string]$Filter = $null, [string]$Namespace = 'root\cimv2')
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return ,@(Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop) }
            return ,@(Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop)
        }
    }
    catch { }
    try {
        if ($Filter) { return ,@(Get-WmiObject -Class $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop) }
        return ,@(Get-WmiObject -Class $Class -Namespace $Namespace -ErrorAction Stop)
    }
    catch { Write-SectionWarning -Message ("CIM/WMI query {0} failed: {1}" -f $Class, (ConvertTo-SafeError -ErrorRecord $_)); return ,@() }
}

function Test-CmdletAvailable {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-CmdletParameter {
    param([string]$Cmdlet, [string]$Parameter)
    try {
        $c = Get-Command -Name $Cmdlet -ErrorAction Stop
        return [bool]($c.Parameters.ContainsKey($Parameter))
    }
    catch { return $false }
}

function Get-FileSha256Prefix {
    # First 12 hex characters of the file's SHA-256, for correlation only.
    param([string]$Path)
    $fs = $null; $sha = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $h   = $sha.ComputeHash($fs)
        return [BitConverter]::ToString($h, 0, 6).Replace('-', '').ToLowerInvariant()
    }
    catch { return $null }
    finally {
        if ($null -ne $fs) { $fs.Dispose() }
        if ($null -ne $sha) { $sha.Dispose() }
    }
}

# ---------------------------------------------------------------------------------------
# Section runner: every section is timed, try/caught, and its failure recorded.
# ---------------------------------------------------------------------------------------
function Invoke-Section {
    param(
        [string]$Key,
        [string]$Name,
        [scriptblock]$Script,
        [switch]$AlwaysRun
    )
    Write-Status -Level 'HEAD' -Message ('--- {0} ---' -f $Name)
    $script:CurrentWarnings = New-Object System.Collections.Generic.List[string]
    $sw     = [System.Diagnostics.Stopwatch]::StartNew()
    $result = $null
    $status = 'OK'
    $errorText = $null
    if (-not $AlwaysRun -and (Test-PastDeadline)) {
        $status = 'SKIPPED_DEADLINE'
        $result = [ordered]@{ Note = ('Section not started: the -MaxMinutes deadline ({0} min) had passed.' -f $script:MaxMinutes) }
    }
    else {
        try {
            $raw = & $Script
            # A section returns one ordered dictionary; if stray pipeline output slipped through,
            # keep the last dictionary that was emitted.
            if ($raw -is [System.Collections.IDictionary]) { $result = $raw }
            elseif ($raw -is [array]) {
                foreach ($item in $raw) { if ($item -is [System.Collections.IDictionary]) { $result = $item } }
            }
            else { $result = $raw }
        }
        catch {
            if (Test-DeadlineException -ErrorRecord $_) {
                $status = 'SKIPPED_DEADLINE'
                $errorText = 'Stopped at the -MaxMinutes deadline before the section completed.'
            }
            else {
                $status    = 'FAIL'
                $errorText = ConvertTo-SafeError -ErrorRecord $_
                [void]$script:FailedSections.Add($Name)
            }
        }
    }
    $sw.Stop()
    if ($status -eq 'OK' -and $script:CurrentWarnings.Count -gt 0) { $status = 'WARN' }
    $script:Sections[$Key]    = $result
    $script:SectionMeta[$Key] = [ordered]@{
        Name      = $Name
        Status    = $status
        ElapsedMs = [int]$sw.ElapsedMilliseconds
        Error     = $errorText
        Warnings  = @($script:CurrentWarnings.ToArray())
    }
    $script:CurrentWarnings = $null
    $msg = ('{0} ({1} ms)' -f $Name, [int]$sw.ElapsedMilliseconds)
    if ($status -eq 'FAIL') { Write-Status -Level 'FAIL' -Message ($msg + ' - ' + $errorText) }
    elseif ($status -eq 'SKIPPED_DEADLINE') { Write-Status -Level 'SKIP' -Message ($msg + ' - skipped: -MaxMinutes deadline reached') }
    else { Write-Status -Level $status -Message $msg }
    # Incremental write: a run killed by an RMM timeout or Ctrl-C still leaves discovery.json
    # with every section completed so far.
    try { if (Get-Command -Name 'Write-DiscoveryFiles' -ErrorAction SilentlyContinue) { Write-DiscoveryFiles -Partial } } catch { }
}

function Invoke-Guarded {
    # Runs a small collection unit; on failure records a section warning and returns $Default.
    # The result is returned with the unary comma so that an empty array stays an empty array:
    # 'return (& $Script)' unrolled even a ',@()' result to $null, and @($null).Count is 1,
    # which is how IsSmtpRelay came out true on every clean server.
    param([string]$What, [scriptblock]$Script, $Default = $null)
    try {
        $r = & $Script
        return ,$r
    }
    catch {
        if (Test-DeadlineException -ErrorRecord $_) {
            Write-SectionWarning -Message ('{0}: stopped at the -MaxMinutes deadline (partial or no data)' -f $What)
            return ,$Default
        }
        Write-SectionWarning -Message ('{0}: {1}' -f $What, (ConvertTo-SafeError -ErrorRecord $_))
        return ,$Default
    }
}

# ---------------------------------------------------------------------------------------
# Exchange version mapping (works from registry / AD / file version, no Exchange tools needed)
# ---------------------------------------------------------------------------------------
# Exchange 2010 SP3 update rollups (14.3.<build>). RU level drives supportability and the
# TLS/.NET position for a coexistence hop. Source: Microsoft "Exchange Server build numbers
# and release dates", checked September 2026.
$script:Ex2010Sp3Builds = @{ 123 = 'SP3 RTM'; 146 = 'SP3 RU1'; 158 = 'SP3 RU2'; 169 = 'SP3 RU3'; 174 = 'SP3 RU4'; 181 = 'SP3 RU5';
    195 = 'SP3 RU6'; 210 = 'SP3 RU7'; 224 = 'SP3 RU8'; 235 = 'SP3 RU9'; 248 = 'SP3 RU10'; 266 = 'SP3 RU11'; 279 = 'SP3 RU12';
    294 = 'SP3 RU13'; 301 = 'SP3 RU14'; 319 = 'SP3 RU15'; 336 = 'SP3 RU16'; 352 = 'SP3 RU17'; 361 = 'SP3 RU18'; 382 = 'SP3 RU19';
    389 = 'SP3 RU20'; 399 = 'SP3 RU21'; 411 = 'SP3 RU22'; 417 = 'SP3 RU23'; 419 = 'SP3 RU24'; 435 = 'SP3 RU25'; 442 = 'SP3 RU26';
    452 = 'SP3 RU27'; 461 = 'SP3 RU28'; 468 = 'SP3 RU29'; 496 = 'SP3 RU30'; 509 = 'SP3 RU31'; 513 = 'SP3 RU32' }
# Exchange 2013 (15.0.<build>). CU20 = 1367, CU21 = 1395, CU22 = 1473, CU23 = 1497 (the only supported 2013 build).
$script:Ex2013Builds = @{ 516 = 'RTM'; 620 = 'CU1'; 712 = 'CU2'; 775 = 'CU3'; 847 = 'SP1 (CU4)'; 913 = 'CU5'; 995 = 'CU6';
    1044 = 'CU7'; 1076 = 'CU8'; 1104 = 'CU9'; 1130 = 'CU10'; 1156 = 'CU11'; 1178 = 'CU12'; 1210 = 'CU13'; 1236 = 'CU14';
    1263 = 'CU15'; 1293 = 'CU16'; 1320 = 'CU17'; 1347 = 'CU18'; 1365 = 'CU19'; 1367 = 'CU20'; 1395 = 'CU21'; 1473 = 'CU22'; 1497 = 'CU23' }
$script:Ex2016Builds = @{ 225 = 'RTM'; 396 = 'CU1'; 466 = 'CU2'; 544 = 'CU3'; 669 = 'CU4'; 845 = 'CU5'; 1034 = 'CU6';
    1261 = 'CU7'; 1415 = 'CU8'; 1466 = 'CU9'; 1531 = 'CU10'; 1591 = 'CU11'; 1713 = 'CU12'; 1779 = 'CU13'; 1847 = 'CU14';
    1913 = 'CU15'; 1979 = 'CU16'; 2044 = 'CU17'; 2106 = 'CU18'; 2176 = 'CU19'; 2242 = 'CU20'; 2308 = 'CU21'; 2375 = 'CU22'; 2507 = 'CU23' }
$script:Ex2019Builds = @{ 221 = 'RTM'; 330 = 'CU1'; 397 = 'CU2'; 464 = 'CU3'; 529 = 'CU4'; 595 = 'CU5'; 659 = 'CU6';
    721 = 'CU7'; 792 = 'CU8'; 858 = 'CU9'; 922 = 'CU10'; 986 = 'CU11'; 1118 = 'CU12'; 1258 = 'CU13'; 1544 = 'CU14'; 1748 = 'CU15' }
$script:ExSeFirstBuild = 2562   # Exchange Server Subscription Edition RTM = 15.2.2562.x
# SE cumulative updates by build. As at September 2026 only RTM (2562) has shipped; security
# updates bump the fourth component only (RTM Sep26SU = 15.2.2562.49). Add CU1+ here when released.
$script:ExSeBuilds = @{ 2562 = 'RTM' }

function Get-ExchangeProductName {
    param([int]$Major, [int]$Minor, [int]$Build, [int]$Revision = -1)
    $family = 'Unknown'; $level = ''
    switch ($Major) {
        8  { $family = 'Exchange Server 2007' }
        14 {
            $family = 'Exchange Server 2010'
            $level = switch ($Minor) { 0 { 'RTM' } 1 { 'SP1' } 2 { 'SP2' } 3 { 'SP3' } default { "SP$Minor" } }
            if ($Minor -eq 3) {
                if ($script:Ex2010Sp3Builds.ContainsKey($Build)) { $level = $script:Ex2010Sp3Builds[$Build] }
                elseif ($Build -gt 513) { $level = 'SP3 later than RU32 (build not in table)' }
                elseif ($Build -gt 123) { $level = ('SP3 RU level unrecognised (build {0})' -f $Build) }
            }
        }
        15 {
            switch ($Minor) {
                0 { $family = 'Exchange Server 2013'; if ($script:Ex2013Builds.ContainsKey($Build)) { $level = $script:Ex2013Builds[$Build] } elseif ($Build -gt 1497) { $level = 'later than CU23' } }
                1 { $family = 'Exchange Server 2016'; if ($script:Ex2016Builds.ContainsKey($Build)) { $level = $script:Ex2016Builds[$Build] } elseif ($Build -gt 2507) { $level = 'later than CU23' } }
                2 {
                    if ($Build -ge $script:ExSeFirstBuild) {
                        $family = 'Exchange Server Subscription Edition (SE)'
                        if ($script:ExSeBuilds.ContainsKey($Build)) {
                            $level = $script:ExSeBuilds[$Build]
                            if ($Revision -ge 0) { $level += (' (15.2.{0}.{1}; security-update level is the 4th component)' -f $Build, $Revision) }
                        }
                        else { $level = ('CU later than the table in this script (build {0})' -f $Build) }
                    }
                    else {
                        $family = 'Exchange Server 2019'
                        if ($script:Ex2019Builds.ContainsKey($Build)) { $level = $script:Ex2019Builds[$Build] } elseif ($Build -gt 1748) { $level = 'later than CU15' }
                    }
                }
                default { $family = 'Exchange Server SE or newer (unrecognised 15.x minor version)' }
            }
        }
        default { if ($Major -gt 15) { $family = 'Exchange Server SE or newer (unrecognised major version)' } }
    }
    if ($level) { return ('{0} {1}' -f $family, $level) }
    return $family
}

function ConvertFrom-ExchangeVersionString {
    # Parses 'Version 15.2 (Build 2562.17)' or '15.2.2562.17' into a friendly name.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text -match 'Version\s+(\d+)\.(\d+)\s+\(Build\s+(\d+)\.(\d+)\)') {
        return (Get-ExchangeProductName -Major ([int]$Matches[1]) -Minor ([int]$Matches[2]) -Build ([int]$Matches[3]) -Revision ([int]$Matches[4]))
    }
    if ($Text -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)') {
        return (Get-ExchangeProductName -Major ([int]$Matches[1]) -Minor ([int]$Matches[2]) -Build ([int]$Matches[3]) -Revision ([int]$Matches[4]))
    }
    return $null
}

function ConvertTo-ExchangeVersion {
    # 'Version 15.1 (Build 2507.6)' or '15.1.2507.6' -> [version] for ordering; $null if unparseable.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        if ($Text -match 'Version\s+(\d+)\.(\d+)\s+\(Build\s+(\d+)\.(\d+)\)') { return [version]('{0}.{1}.{2}.{3}' -f $Matches[1], $Matches[2], $Matches[3], $Matches[4]) }
        if ($Text -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)') { return [version]('{0}.{1}.{2}.{3}' -f $Matches[1], $Matches[2], $Matches[3], $Matches[4]) }
        if ($Text -match '^(\d+)\.(\d+)\.(\d+)') { return [version]('{0}.{1}.{2}.0' -f $Matches[1], $Matches[2], $Matches[3]) }
    }
    catch { }
    return $null
}

function Get-ExchangeFamilyFromVersion {
    # Coarse family label used for org-wide min/max decisions.
    param([version]$Version)
    if ($null -eq $Version) { return $null }
    if ($Version.Major -le 8) { return '2007 or earlier' }
    if ($Version.Major -eq 14) { return '2010' }
    if ($Version.Major -eq 15 -and $Version.Minor -eq 0) { return '2013' }
    if ($Version.Major -eq 15 -and $Version.Minor -eq 1) { return '2016' }
    if ($Version.Major -eq 15 -and $Version.Minor -eq 2 -and $Version.Build -lt $script:ExSeFirstBuild) { return '2019' }
    if ($Version.Major -eq 15 -and $Version.Minor -eq 2) { return 'SE' }
    return 'newer than SE'
}

function Get-ExchangeSchemaVersionName {
    # ms-Exch-Schema-Version-Pt rangeUpper. 2007: 10628 RTM, 11116 SP1, 14622 SP2, 14625 SP3.
    # 2010: 14726 RTM/SP1, 14732 SP2, 14734 SP3. 2013: 15132-15312. 2016: 15317-15334. 2019/SE: 17000-17003.
    param([int]$RangeUpper)
    if ($RangeUpper -le 0) { return 'Not present' }
    if ($RangeUpper -le 14625) { return 'Exchange 2007 or earlier' }
    if ($RangeUpper -lt 15000) { return 'Exchange 2010' }
    if ($RangeUpper -lt 15317) { return 'Exchange 2013' }
    if ($RangeUpper -lt 17000) { return 'Exchange 2016' }
    if ($RangeUpper -le 17003) { return 'Exchange 2019 / SE' }
    return 'Exchange SE or newer'
}

$script:ServerRoleBits = [ordered]@{ 2 = 'Mailbox'; 4 = 'ClientAccess'; 16 = 'UnifiedMessaging'; 32 = 'HubTransport'; 64 = 'Edge'; 4096 = 'Provisioned'; 16384 = 'FrontEndTransport(2013+)' }
function ConvertFrom-ServerRoleMask {
    param([long]$Mask)
    $known = @{ '16385' = 'ClientAccess (2013)'; '16439' = 'Mailbox (2013+ multi-role)'; '54' = 'Mailbox+ClientAccess+HubTransport (2010 typical)' }
    if ($known.ContainsKey("$Mask")) { return $known["$Mask"] }
    $names = @()
    foreach ($bit in $script:ServerRoleBits.Keys) { if (($Mask -band $bit) -ne 0) { $names += $script:ServerRoleBits[$bit] } }
    if ($names.Count -eq 0) { return "Unknown ($Mask)" }
    return ($names -join '+')
}

# ---------------------------------------------------------------------------------------
# ADSI helpers (read-only; work on any domain-joined machine without RSAT)
# ---------------------------------------------------------------------------------------
function Get-RootDse {
    # [ADSI] binds lazily and the cast never throws, so a property is forced here: with no
    # domain controller reachable this returns $null and the caller's warning is reachable.
    try {
        $r = [ADSI]'LDAP://RootDSE'
        $nc = $r.Properties['defaultNamingContext']
        if ($null -eq $nc -or $nc.Count -eq 0 -or [string]::IsNullOrWhiteSpace("$($nc[0])")) { return $null }
        return $r
    }
    catch { return $null }
}

function Get-AdsiPropertyValue {
    param($Entry, [string]$Name)
    try {
        $v = $Entry.Properties[$Name]
        if ($null -eq $v -or $v.Count -eq 0) { return $null }
        if ($v.Count -eq 1) { return $v[0] }
        return ,@($v)
    }
    catch { return $null }
}

function Search-Directory {
    # Wraps System.DirectoryServices.DirectorySearcher (read-only LDAP query). Server and
    # client time limits are always set. With -RowAction the rows are streamed to the
    # scriptblock one at a time and never materialised (used for the forest-wide recipient
    # count, which at 100k objects would otherwise hold hundreds of MB in a 32-bit host).
    param(
        [string]$SearchBase,          # e.g. 'LDAP://CN=Configuration,DC=x,DC=y' or 'GC://DC=x,DC=y'
        [string]$Filter,
        [string[]]$Properties,
        [string]$Scope = 'Subtree',
        [int]$SizeLimit = 0,
        [int]$TimeoutSeconds = 120,
        [scriptblock]$RowAction = $null
    )
    $searcher = $null
    $results  = $null
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry($SearchBase)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter      = $Filter
        $searcher.SearchScope = $Scope
        $searcher.PageSize    = 1000
        $searcher.CacheResults = $false
        $searcher.ServerTimeLimit     = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $searcher.ServerPageTimeLimit = [TimeSpan]::FromSeconds([math]::Min(60, $TimeoutSeconds))
        $searcher.ClientTimeout       = [TimeSpan]::FromSeconds($TimeoutSeconds + 30)
        if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
        $searcher.PropertiesToLoad.Clear()
        foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
        $results = $searcher.FindAll()
        if ($null -ne $RowAction) {
            $n = 0
            foreach ($r in $results) {
                $n++
                & $RowAction $r
                if (($n % 2000) -eq 0) { Assert-Deadline }
            }
            return $n
        }
        $out = New-Object System.Collections.ArrayList
        foreach ($r in $results) {
            $o = [ordered]@{}
            foreach ($p in $Properties) {
                $lp = $p.ToLowerInvariant()
                if ($r.Properties.Contains($lp)) {
                    $vals = $r.Properties[$lp]
                    if ($vals.Count -eq 1) { $o[$p] = $vals[0] } else { $o[$p] = @($vals) }
                }
                else { $o[$p] = $null }
            }
            [void]$out.Add($o)
            if (($out.Count % 2000) -eq 0) { Assert-Deadline }
        }
        return ,@($out.ToArray())
    }
    catch { throw }
    finally {
        if ($null -ne $results) { try { $results.Dispose() } catch { } }
        if ($null -ne $searcher) { $searcher.Dispose() }
    }
}

function Get-AdsiPropertyString {
    # Single-valued attribute from a SearchResult, as string ('' when absent).
    param($SearchResult, [string]$Name)
    try {
        $lp = $Name.ToLowerInvariant()
        if ($SearchResult.Properties.Contains($lp) -and $SearchResult.Properties[$lp].Count -gt 0) { return "$($SearchResult.Properties[$lp][0])" }
    }
    catch { }
    return ''
}

function Resolve-HostAddressBounded {
    # DNS resolution with a hard wall-clock bound (Dns.GetHostAddresses has none and can
    # hang for seconds on a stale record). Returns the first IPv4 address or $null.
    param([string]$HostName, [int]$TimeoutMs = 2000)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }
    try {
        $ar = [System.Net.Dns]::BeginGetHostAddresses($HostName, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $null }
        $addrs = [System.Net.Dns]::EndGetHostAddresses($ar)
        foreach ($a in @($addrs)) { if ($a.AddressFamily -eq 'InterNetwork') { return "$a" } }
        if (@($addrs).Count -gt 0) { return "$($addrs[0])" }
    }
    catch { }
    return $null
}

function Get-DnFirstComponent {
    # 'CN=Site,CN=Sites,...' -> 'Site'; canonical 'contoso.com/Configuration/Sites/Site' -> 'Site'.
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return $null }
    if ($Dn -match '^CN=([^,]+)') { return $Matches[1] }
    if ($Dn -match '/([^/]+)$') { return $Matches[1] }
    return $Dn
}

function ConvertTo-DomainFqdn {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return $null }
    $parts = @()
    foreach ($m in [regex]::Matches($Dn, 'DC=([^,]+)', 'IgnoreCase')) { $parts += $m.Groups[1].Value }
    if ($parts.Count -eq 0) { return $null }
    return ($parts -join '.')
}

# ---------------------------------------------------------------------------------------
# Exchange management tools loader. Dot-sourced from the main flow so that snap-ins,
# dot-sourced RemoteExchange.ps1 functions and implicit remoting modules land in the
# script scope. Everything here affects only the current PowerShell session.
# ---------------------------------------------------------------------------------------
$script:ExchangeToolsLoader = {
    $attempts = New-Object System.Collections.ArrayList
    $loaded = $false
    $method = 'None'

    # 0. Already present (the launcher was run from an Exchange Management Shell, or the
    #    operator loaded the snap-in themselves). Nothing to load.
    if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) {
        $loaded = $true
        $method = 'Pre-loaded in the calling session (Exchange Management Shell or operator-loaded snap-in)'
        [void]$attempts.Add('Pre-loaded: Get-ExchangeServer already available')
    }
    elseif (Get-Command -Name 'Get-RemoteMailbox' -ErrorAction SilentlyContinue) {
        $loaded = $true
        $method = 'Pre-loaded in the calling session (recipient-management cmdlets only)'
        $script:Ctx.ExchangeToolsMode = 'RecipientManagementOnly'
        [void]$attempts.Add('Pre-loaded: Get-RemoteMailbox already available')
    }
    # 1. Exchange 2013 / 2016 / 2019 / SE local snap-in
    if (-not $loaded) {
        try {
            if (Get-PSSnapin -Registered -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue) {
                Add-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction Stop
                if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) { $loaded = $true; $method = 'Snap-in: Microsoft.Exchange.Management.PowerShell.SnapIn' }
            }
            [void]$attempts.Add('SnapIn (2013+): ' + $(if ($loaded) { 'loaded' } else { 'not registered or no cmdlets' }))
        }
        catch { [void]$attempts.Add('SnapIn (2013+): ' + (ConvertTo-SafeError -ErrorRecord $_)) }
    }
    # 2. Exchange 2010 snap-in
    if (-not $loaded) {
        try {
            if (Get-PSSnapin -Registered -Name 'Microsoft.Exchange.Management.PowerShell.E2010' -ErrorAction SilentlyContinue) {
                Add-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.E2010' -ErrorAction Stop
                if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) { $loaded = $true; $method = 'Snap-in: Microsoft.Exchange.Management.PowerShell.E2010' }
            }
            [void]$attempts.Add('E2010 snap-in: ' + $(if ($loaded) { 'loaded' } else { 'not registered or no cmdlets' }))
        }
        catch { [void]$attempts.Add('E2010 snap-in: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
    }
    # 3. Recipient-management-only snap-in (Exchange Management Tools role, 2019 CU12+ / SE)
    if (-not $loaded) {
        try {
            $rm = @(Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*RecipientManagement*' })
            if ($rm.Count -gt 0) {
                Add-PSSnapin -Name $rm[0].Name -ErrorAction Stop
                if (Get-Command -Name 'Get-RemoteMailbox' -ErrorAction SilentlyContinue) {
                    $loaded = $true; $method = 'Snap-in: ' + $rm[0].Name
                    $script:Ctx.ExchangeToolsMode = 'RecipientManagementOnly'
                }
            }
            [void]$attempts.Add('RecipientManagement snap-in: ' + $(if ($loaded) { 'loaded' } else { 'not registered' }))
        }
        catch { [void]$attempts.Add('RecipientManagement snap-in: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
    }
    # 4. RemoteExchange.ps1 + Connect-ExchangeServer -auto (creates an implicit remoting session)
    if (-not $loaded -and $env:ExchangeInstallPath) {
        try {
            $re = Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1'
            if (Test-Path -LiteralPath $re) {
                . $re *> $null
                if (Get-Command -Name 'Connect-ExchangeServer' -ErrorAction SilentlyContinue) {
                    Connect-ExchangeServer -auto *> $null
                }
                if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) { $loaded = $true; $method = 'RemoteExchange.ps1 + Connect-ExchangeServer -auto (implicit remoting)' }
            }
            [void]$attempts.Add('RemoteExchange.ps1: ' + $(if ($loaded) { 'loaded' } else { 'not present or connect failed' }))
        }
        catch { [void]$attempts.Add('RemoteExchange.ps1: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
    }
    # 5. Implicit remoting to the local server's /PowerShell virtual directory (any version
    #    with a server role installed locally; 2010 supports it too). Session-scoped, with
    #    open/operation timeouts, and removed at the end of the run. Nothing is written.
    if (-not $loaded -and $script:Ctx.ExchangeInstalled) {
        try {
            $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
            $uri  = 'http://{0}/PowerShell/' -f $fqdn
            $so   = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 300000 -IdleTimeout 900000 -CancelTimeout 15000
            $sess = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Authentication Kerberos -SessionOption $so -ErrorAction Stop
            $script:ExchangeSession = $sess
            $mod  = Import-PSSession -Session $sess -DisableNameChecking -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
            if ($mod) { Import-Module $mod -Global -DisableNameChecking -ErrorAction SilentlyContinue }
            if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) { $loaded = $true; $method = 'Implicit remoting to local /PowerShell virtual directory' }
            [void]$attempts.Add('Implicit remoting: ' + $(if ($loaded) { 'loaded' } else { 'session opened but no cmdlets' }))
        }
        catch { [void]$attempts.Add('Implicit remoting: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
    }

    $script:Ctx.ExchangeToolsLoaded = $loaded
    $script:Ctx.ExchangeToolsMethod = $method
    if ($loaded -and $script:Ctx.ExchangeToolsMode -eq 'None') { $script:Ctx.ExchangeToolsMode = 'Full' }
    $script:Ctx.ExchangeToolsAttempts = @($attempts.ToArray())

    # View the entire forest for recipient counts. This changes only the scope of this
    # PowerShell session (an in-memory setting); it does not write to AD or Exchange.
    $script:Ctx.ViewEntireForestSet = $false
    if ($loaded -and (Get-Command -Name 'Set-ADServerSettings' -ErrorAction SilentlyContinue)) {
        try { Set-ADServerSettings -ViewEntireForest $true -ErrorAction Stop; $script:Ctx.ViewEntireForestSet = $true } catch { }
    }
}

# =======================================================================================
# SECTION B - Host / server sizing
# =======================================================================================
function Get-HostSection {
    $out = [ordered]@{}

    $cs = @(Get-CimSafe -Class 'Win32_ComputerSystem')
    $os = @(Get-CimSafe -Class 'Win32_OperatingSystem')
    $cpu = @(Get-CimSafe -Class 'Win32_Processor')

    # Domain membership must not depend on WMI alone: a corrupt WMI repository (not rare on
    # an old Exchange box) would otherwise report "not domain-joined" and silently disable
    # every AD-based section. Fall back to the environment and to .NET.
    $joinedByWmi = $null
    if ($cs.Count -gt 0) { $joinedByWmi = [bool](Get-PropertySafe -InputObject $cs[0] -Name 'PartOfDomain' -Default $false) }
    $joinedByEnv = $false; $envDomain = $null
    if ($env:USERDNSDOMAIN) { $joinedByEnv = $true; $envDomain = $env:USERDNSDOMAIN }
    $joinedByNet = $false; $netDomain = $null
    try { $cd = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain(); if ($cd) { $joinedByNet = $true; $netDomain = $cd.Name } } catch { }
    $script:Ctx.IsDomainJoined = ($joinedByWmi -eq $true -or $joinedByEnv -or $joinedByNet)
    if ($script:Ctx.IsDomainJoined) {
        if ($cs.Count -gt 0 -and $joinedByWmi) { $script:Ctx.DomainFqdn = Get-PropertySafe -InputObject $cs[0] -Name 'Domain' }
        elseif ($netDomain) { $script:Ctx.DomainFqdn = $netDomain }
        else { $script:Ctx.DomainFqdn = $envDomain }
    }
    $out.DomainJoinDetection = [ordered]@{ Wmi = $joinedByWmi; Environment = $joinedByEnv; DotNet = $joinedByNet; Result = $script:Ctx.IsDomainJoined }
    if ($cs.Count -eq 0) { Write-SectionWarning -Message ('Win32_ComputerSystem could not be read (WMI repository problem?); domain membership taken from environment/.NET: {0}' -f $script:Ctx.IsDomainJoined) }
    elseif ($joinedByWmi -eq $false -and $script:Ctx.IsDomainJoined) { Write-SectionWarning -Message 'WMI reports the machine as not domain-joined but the environment/.NET say it is; treating it as domain-joined.' }

    if ($cs.Count -gt 0) {
        $c = $cs[0]
        $domainRole = switch ([int](Get-PropertySafe -InputObject $c -Name 'DomainRole' -Default -1)) {
            0 { 'Standalone workstation' } 1 { 'Member workstation' } 2 { 'Standalone server' }
            3 { 'Member server' } 4 { 'Backup domain controller' } 5 { 'Primary domain controller' } default { 'Unknown' }
        }
        $manufacturer = "$(Get-PropertySafe -InputObject $c -Name 'Manufacturer')"
        $model        = "$(Get-PropertySafe -InputObject $c -Name 'Model')"
        $hypervisor = 'Physical or undetermined'
        if ($model -match 'Virtual Machine' -and $manufacturer -match 'Microsoft') { $hypervisor = 'Hyper-V (or Azure)' }
        elseif ($manufacturer -match 'VMware') { $hypervisor = 'VMware' }
        elseif ($manufacturer -match 'Xen' -or $model -match 'HVM domU') { $hypervisor = 'Xen / Citrix' }
        elseif ($manufacturer -match 'QEMU|Red Hat' -or $model -match 'KVM') { $hypervisor = 'KVM / QEMU' }
        elseif ($manufacturer -match 'innotek|Oracle' -and $model -match 'VirtualBox') { $hypervisor = 'VirtualBox' }
        elseif ($manufacturer -match 'Nutanix') { $hypervisor = 'Nutanix AHV' }
        elseif ($manufacturer -match 'Amazon') { $hypervisor = 'AWS' }
        elseif ($model -match 'Google') { $hypervisor = 'Google Cloud' }
        $azureAgent = [bool](Get-Service -Name 'WindowsAzureGuestAgent' -ErrorAction SilentlyContinue)
        if ($azureAgent) { $hypervisor = 'Azure (guest agent present)' }
        $hvPresent = Get-PropertySafe -InputObject $c -Name 'HypervisorPresent'

        $out.Computer = [ordered]@{
            HostName             = Protect-Hostname -Value $env:COMPUTERNAME
            DomainRole           = $domainRole
            IsDomainJoined       = $script:Ctx.IsDomainJoined
            Domain               = Protect-Hostname -Value "$(Get-PropertySafe -InputObject $c -Name 'Domain')"
            Manufacturer         = $manufacturer
            Model                = $model
            IsVirtual            = ($hypervisor -ne 'Physical or undetermined')
            Hypervisor           = $hypervisor
            HypervisorPresentFlag = $hvPresent
            PhysicalMemoryGB     = [math]::Round(([double](Get-PropertySafe -InputObject $c -Name 'TotalPhysicalMemory' -Default 0)) / 1GB, 1)
            SocketCount          = Get-PropertySafe -InputObject $c -Name 'NumberOfProcessors'
            LogicalProcessorCount = Get-PropertySafe -InputObject $c -Name 'NumberOfLogicalProcessors'
        }
    }

    $out.Processors = @(foreach ($p in $cpu) {
        Select-SafeProperties -InputObject $p -Properties @('Name', 'NumberOfCores', 'NumberOfLogicalProcessors', 'MaxClockSpeed', 'Manufacturer')
    })
    if ($cpu.Count -gt 0) {
        $cores = 0; foreach ($p in $cpu) { $cores += [int](Get-PropertySafe -InputObject $p -Name 'NumberOfCores' -Default 0) }
        $out.TotalPhysicalCores = $cores
    }

    # WMI can return a Win32_OperatingSystem instance whose properties are empty on a damaged
    # repository (seen on King Springs 15 Sep 2026: the object existed but Caption and Version were
    # blank, so an existence check alone still produced "os_caption= ()"). Treat a blank Caption as
    # no result and fall through to the registry.
    $osCaptionProbe = $(if ($os.Count -gt 0) { "$(Get-PropertySafe -InputObject $os[0] -Name 'Caption')" } else { '' })
    if ($os.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($osCaptionProbe)) {
        $o = $os[0]
        $installDate = $null; $lastBoot = $null
        try { $installDate = Get-PropertySafe -InputObject $o -Name 'InstallDate'; if ($installDate -is [string]) { $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($installDate) } } catch { }
        try { $lastBoot = Get-PropertySafe -InputObject $o -Name 'LastBootUpTime'; if ($lastBoot -is [string]) { $lastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot) } } catch { }
        $uptimeDays = $null
        if ($lastBoot -is [DateTime]) { $uptimeDays = [math]::Round(((Get-Date) - $lastBoot).TotalDays, 1) }
        $out.OperatingSystem = [ordered]@{
            Caption          = Get-PropertySafe -InputObject $o -Name 'Caption'
            Version          = Get-PropertySafe -InputObject $o -Name 'Version'
            BuildNumber      = Get-PropertySafe -InputObject $o -Name 'BuildNumber'
            Architecture     = Get-PropertySafe -InputObject $o -Name 'OSArchitecture'
            InstallDate      = ConvertTo-IsoString -Value $installDate
            LastBoot         = ConvertTo-IsoString -Value $lastBoot
            UptimeDays       = $uptimeDays
            TimeZone         = Invoke-Guarded -What 'TimeZone' -Script { [TimeZoneInfo]::Local.Id }
            SystemDrive      = $env:SystemDrive
            UbrBuildRevision = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
            DisplayVersion   = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'DisplayVersion'
            Source           = 'WMI/CIM'
        }
    }
    else {
        # WMI can be broken on an old Exchange server (seen on a King Springs Exchange 2016 box,
        # 15 Sep 2026, where Win32_OperatingSystem returned nothing). The OS caption is an Azure VM
        # sizing input, so fall back to the registry rather than reporting an empty string.
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $regCaption = Get-RegistryValue -Path $cv -Name 'ProductName'
        $regBuild   = Get-RegistryValue -Path $cv -Name 'CurrentBuildNumber'
        $out.OperatingSystem = [ordered]@{
            Caption          = $(if ($regCaption) { "$regCaption" } else { 'Unknown (WMI unavailable and registry ProductName missing)' })
            Version          = $(if ($regBuild) { "$(Get-RegistryValue -Path $cv -Name 'CurrentVersion').$regBuild" } else { $null })
            BuildNumber      = $regBuild
            Architecture     = $(if ($env:PROCESSOR_ARCHITECTURE -match '64') { '64-bit' } else { '32-bit' })
            InstallDate      = $null
            LastBoot         = $null
            UptimeDays       = $null
            TimeZone         = Invoke-Guarded -What 'TimeZone' -Script { [TimeZoneInfo]::Local.Id }
            SystemDrive      = $env:SystemDrive
            UbrBuildRevision = Get-RegistryValue -Path $cv -Name 'UBR'
            DisplayVersion   = Get-RegistryValue -Path $cv -Name 'DisplayVersion'
            Source           = 'Registry fallback (WMI unavailable)'
        }
        Write-SectionWarning -Message 'Win32_OperatingSystem could not be read; OS details taken from the registry and uptime/install date are unavailable.'
    }

    # Volumes: size and free space only (no labels; labels are free text set by the client).
    $out.Volumes = @(foreach ($d in @(Get-CimSafe -Class 'Win32_LogicalDisk' -Filter 'DriveType=3')) {
        [ordered]@{
            Drive      = Get-PropertySafe -InputObject $d -Name 'DeviceID'
            FileSystem = Get-PropertySafe -InputObject $d -Name 'FileSystem'
            SizeGB     = [math]::Round(([double](Get-PropertySafe -InputObject $d -Name 'Size' -Default 0)) / 1GB, 1)
            FreeGB     = [math]::Round(([double](Get-PropertySafe -InputObject $d -Name 'FreeSpace' -Default 0)) / 1GB, 1)
        }
    })

    # .NET Framework 4.x release (an Exchange SE readiness input)
    $out.DotNetFramework = Invoke-Guarded -What 'DotNet' -Script {
        $release = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release'
        $ver     = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Version'
        $name = 'Unknown'
        if ($null -ne $release) {
            $r = [int]$release
            if ($r -ge 533320) { $name = '4.8.1 or later' } elseif ($r -ge 528040) { $name = '4.8' } elseif ($r -ge 461808) { $name = '4.7.2' }
            elseif ($r -ge 461308) { $name = '4.7.1' } elseif ($r -ge 460798) { $name = '4.7' } elseif ($r -ge 394802) { $name = '4.6.2' }
            elseif ($r -ge 394254) { $name = '4.6.1' } elseif ($r -ge 393295) { $name = '4.6' } elseif ($r -ge 379893) { $name = '4.5.2' }
            elseif ($r -ge 378675) { $name = '4.5.1' } elseif ($r -ge 378389) { $name = '4.5' }
        }
        [ordered]@{ Release = $release; Version = $ver; FriendlyName = $name; ClrVersion = "$([Environment]::Version)" }
    }

    $out.PowerShell = [ordered]@{
        RunningVersion     = "$($PSVersionTable.PSVersion)"
        Edition            = $(if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' })
        EngineVersionInRegistry = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -Name 'PowerShellVersion'
        PowerShell7Present = [bool](Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue)
        Is64BitProcess     = [Environment]::Is64BitProcess
        ExecutionPolicyEffective = Invoke-Guarded -What 'ExecutionPolicy' -Script { "$(Get-ExecutionPolicy)" }
        ExecutionPolicyMachine   = Invoke-Guarded -What 'ExecutionPolicyMachine' -Script { "$(Get-ExecutionPolicy -Scope LocalMachine)" }
    }

    $out.RunningAs = Invoke-Guarded -What 'RunningAs' -Script {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        [ordered]@{
            Account    = Protect-Account -Value $id.Name
            IsElevated = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            IsDomainAccount = ($id.Name -notlike ("$env:COMPUTERNAME\*"))
        }
    }

    return $out
}

# =======================================================================================
# SECTION H - Active Directory
# =======================================================================================
function Get-ActiveDirectorySection {
    $out = [ordered]@{}
    if (-not $script:Ctx.IsDomainJoined) {
        $out.Note = 'This machine is not domain-joined; Active Directory discovery skipped.'
        return $out
    }

    $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue | Select-Object -First 1
    $out.ActiveDirectoryModule = [ordered]@{
        Present = [bool]$adModule
        Version = $(if ($adModule) { "$($adModule.Version)" } else { $null })
        Note    = 'All collection uses System.DirectoryServices against the configuration partition (no RSAT needed, no per-DC contact). The module is only reported as present/absent.'
    }

    $rootDse = Get-RootDse
    if ($null -ne $rootDse) {
        $script:Ctx.ConfigNC     = "$(Get-AdsiPropertyValue -Entry $rootDse -Name 'configurationNamingContext')"
        $script:Ctx.RootDomainNC = "$(Get-AdsiPropertyValue -Entry $rootDse -Name 'rootDomainNamingContext')"
        $script:Ctx.DefaultNC    = "$(Get-AdsiPropertyValue -Entry $rootDse -Name 'defaultNamingContext')"
        $script:Ctx.SchemaNC     = "$(Get-AdsiPropertyValue -Entry $rootDse -Name 'schemaNamingContext')"
        $dnsHost = "$(Get-AdsiPropertyValue -Entry $rootDse -Name 'dnsHostName')"
        if ($dnsHost) { $script:Ctx.DcHostname = $dnsHost }
        $out.RootDse = [ordered]@{
            ServedBy                 = Protect-Hostname -Value $dnsHost
            ForestFunctionality      = Get-AdsiPropertyValue -Entry $rootDse -Name 'forestFunctionality'
            DomainFunctionality      = Get-AdsiPropertyValue -Entry $rootDse -Name 'domainFunctionality'
            DomainControllerFunctionality = Get-AdsiPropertyValue -Entry $rootDse -Name 'domainControllerFunctionality'
            IsGlobalCatalogReady     = Get-AdsiPropertyValue -Entry $rootDse -Name 'isGlobalCatalogReady'
            ForestDnsName            = Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $script:Ctx.RootDomainNC)
            DomainDnsName            = Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $script:Ctx.DefaultNC)
        }
        $script:Ctx.ForestFqdn = ConvertTo-DomainFqdn -Dn $script:Ctx.RootDomainNC
    }
    else { Write-SectionWarning -Message 'RootDSE could not be read (no domain controller reachable?). AD-based discovery is skipped.' }

    # Domain partitions from the crossRef objects in the configuration partition. This is the
    # authoritative domain list and it is read from the local DC only; nothing contacts the
    # other domains yet.
    $script:Ctx.DomainNcs = @()
    if ($script:Ctx.ConfigNC) {
        $out.Domains = Invoke-Guarded -What 'Domain crossRefs' -Script {
            $rows = @(Search-Directory -SearchBase ("LDAP://CN=Partitions," + $script:Ctx.ConfigNC) -Filter '(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))' -Properties @('nCName', 'dnsRoot', 'nETBIOSName', 'msDS-Behavior-Version') -Scope 'OneLevel' -TimeoutSeconds 60)
            $list = @()
            foreach ($r in $rows) {
                $nc = "$($r['nCName'])"
                if ($nc) { $script:Ctx.DomainNcs += $nc }
                $list += [ordered]@{
                    DnsRoot               = Protect-Hostname -Value "$($r['dnsRoot'])"
                    NetBiosName           = Protect-Hostname -Value "$($r['nETBIOSName'])"
                    DomainFunctionalLevel = $r['msDS-Behavior-Version']
                    IsThisDomain          = ($nc -ieq "$($script:Ctx.DefaultNC)")
                }
            }
            ,$list
        }
        $out.DomainCount = Get-SafeCount -Value $out.Domains
    }
    if ($script:Ctx.DomainNcs.Count -eq 0 -and $script:Ctx.DefaultNC) { $script:Ctx.DomainNcs = @($script:Ctx.DefaultNC) }

    # Forest / domain summary from .NET (names, modes and FSMO owners are read from the local
    # DC's copy of the directory; no per-DC contact).
    $forest = Invoke-Guarded -What 'Forest' -Script { [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() }
    if ($null -ne $forest) {
        $out.Forest = Invoke-Guarded -What 'Forest details' -Script {
            [ordered]@{
                Name                 = Protect-Hostname -Value $forest.Name
                ForestMode           = "$($forest.ForestMode)"
                RootDomain           = Protect-Hostname -Value $forest.RootDomain.Name
                SchemaMaster         = Protect-Hostname -Value "$($forest.SchemaRoleOwner)"
                DomainNamingMaster   = Protect-Hostname -Value "$($forest.NamingRoleOwner)"
            }
        }
    }
    $domain = Invoke-Guarded -What 'Domain' -Script { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() }
    if ($null -ne $domain) {
        $out.Domain = Invoke-Guarded -What 'Domain details' -Script {
            [ordered]@{
                Name                 = Protect-Hostname -Value $domain.Name
                DomainMode           = "$($domain.DomainMode)"
                PdcEmulator          = Protect-Hostname -Value "$($domain.PdcRoleOwner)"
                RidMaster            = Protect-Hostname -Value "$($domain.RidRoleOwner)"
                InfrastructureMaster = Protect-Hostname -Value "$($domain.InfrastructureRoleOwner)"
                ParentDomain         = $(if ($domain.Parent) { Protect-Hostname -Value $domain.Parent.Name } else { $null })
                ChildDomainCount     = Get-SafeCount -Value $domain.Children
            }
        }
        if (-not $script:Ctx.DcHostname) { $script:Ctx.DcHostname = "$($domain.PdcRoleOwner)" }
    }

    if ($script:Ctx.ConfigNC) {
        $cfg = $script:Ctx.ConfigNC

        # Sites: total count plus the local site only (name, subnets, servers). Every site in
        # the forest is not needed for the design and is a large disclosure.
        $out.SiteCount = Invoke-Guarded -What 'Site count' -Script {
            @(Search-Directory -SearchBase ("LDAP://CN=Sites," + $cfg) -Filter '(objectClass=site)' -Properties @('name') -Scope 'OneLevel' -TimeoutSeconds 60).Count
        }
        $script:Ctx.LocalSiteName = $null
        $out.LocalSite = Invoke-Guarded -What 'Local AD site' -Script {
            $site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
            $script:Ctx.LocalSiteName = "$($site.Name)"
            $subnets = @(); $i = 0
            foreach ($n in $site.Subnets) { $i++; if ($i -gt 50) { break }; $subnets += "$($n.Name)" }
            [ordered]@{
                Name        = Protect-Hostname -Value $site.Name
                ServerCount = Get-SafeCount -Value $site.Servers
                SubnetCount = Get-SafeCount -Value $site.Subnets
                Subnets     = $subnets
                Note        = 'Only the site containing this computer is listed.'
            }
        }
        $out.SubnetCount = Invoke-Guarded -What 'Subnet count' -Script {
            @(Search-Directory -SearchBase ("LDAP://CN=Subnets,CN=Sites," + $cfg) -Filter '(objectClass=subnet)' -Properties @('name') -Scope 'OneLevel' -TimeoutSeconds 60).Count
        }
        $localSiteName = $script:Ctx.LocalSiteName

        # Domain controllers from the configuration partition (server + NTDS Settings objects)
        # joined to the computer objects of each domain for OS versions. No DC is contacted
        # individually, so a dead DAG-era DC or a decommissioned DC cannot stall the run.
        $out.DomainControllers = Invoke-Guarded -What 'Domain controllers (config partition)' -Script {
            $servers = @(Search-Directory -SearchBase ("LDAP://CN=Sites," + $cfg) -Filter '(objectClass=server)' -Properties @('distinguishedName', 'name', 'dNSHostName', 'serverReference') -Scope 'Subtree' -TimeoutSeconds 90)
            $ntds    = @(Search-Directory -SearchBase ("LDAP://CN=Sites," + $cfg) -Filter '(objectClass=nTDSDSA)' -Properties @('distinguishedName', 'options', 'objectClass', 'msDS-HasDomainNCs') -Scope 'Subtree' -TimeoutSeconds 90)
            $ntdsByServerDn = @{}
            foreach ($n in $ntds) {
                $dn = "$($n['distinguishedName'])"
                if ($dn -match '^CN=NTDS Settings,(?<srv>.+)$') { $ntdsByServerDn[$Matches['srv'].ToLowerInvariant()] = $n }
            }
            # OS versions from the computer objects (one query per domain, guarded individually).
            $osByDn = @{}
            foreach ($nc in $script:Ctx.DomainNcs) {
                try {
                    foreach ($c in @(Search-Directory -SearchBase ("LDAP://" + $nc) -Filter '(&(objectClass=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=521)))' -Properties @('distinguishedName', 'operatingSystem', 'operatingSystemVersion') -Scope 'Subtree' -TimeoutSeconds 60 -SizeLimit 500)) {
                        $osByDn["$($c['distinguishedName'])".ToLowerInvariant()] = $c
                    }
                }
                catch { Write-SectionWarning -Message ('DC computer objects for one domain could not be read: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
            }
            $dcs = @(); $count = 0; $resolved = 0
            foreach ($s in $servers) {
                $sdn = "$($s['distinguishedName'])"
                $n = $ntdsByServerDn[$sdn.ToLowerInvariant()]
                if ($null -eq $n) { continue }   # a server object without NTDS Settings is not a DC
                $count++
                if ($count -gt 100) { break }
                $siteName = $null; if ($sdn -match 'CN=Servers,CN=(?<site>[^,]+),CN=Sites,') { $siteName = $Matches['site'] }
                $isGc = $false; try { $isGc = (([int]"$($n['options'])" -band 1) -ne 0) } catch { }
                $isRodc = $false; try { $isRodc = (@($n['objectClass']) -contains 'nTDSDSARO') } catch { }
                $osRow = $null; $ref = "$($s['serverReference'])"; if ($ref) { $osRow = $osByDn[$ref.ToLowerInvariant()] }
                $domainOfDc = $null; if ($ref) { $domainOfDc = Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $ref) }
                $ip = $null
                $fqdn = "$($s['dNSHostName'])"
                if ($fqdn -and $localSiteName -and $siteName -ieq $localSiteName -and $resolved -lt 20 -and -not (Test-PastDeadline)) { $resolved++; $ip = Resolve-HostAddressBounded -HostName $fqdn -TimeoutMs 2000 }
                $dcs += [ordered]@{
                    Name            = Protect-Hostname -Value "$($s['name'])"
                    Domain          = $domainOfDc
                    Site            = Protect-Hostname -Value $siteName
                    IsInLocalSite   = [bool]($localSiteName -and ($siteName -ieq $localSiteName))
                    IPAddress       = $ip
                    OperatingSystem = $(if ($osRow) { "$($osRow['operatingSystem'])" } else { $null })
                    OSVersion       = $(if ($osRow) { "$($osRow['operatingSystemVersion'])" } else { $null })
                    IsGlobalCatalog = $isGc
                    IsReadOnly      = $isRodc
                }
            }
            ,$dcs
        }
        $out.DomainControllerCount = Get-SafeCount -Value $out.DomainControllers
        $out.GlobalCatalogCount = Get-SafeCount -Value @($out.DomainControllers | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['IsGlobalCatalog'] -eq $true })

        # Trusts from the trustedDomain objects of this domain (no trust partner is contacted).
        $out.Trusts = Invoke-Guarded -What 'Trusts' -Script {
            $rows = @(Search-Directory -SearchBase ("LDAP://CN=System," + $script:Ctx.DefaultNC) -Filter '(objectClass=trustedDomain)' -Properties @('name', 'flatName', 'trustDirection', 'trustType', 'trustAttributes') -Scope 'OneLevel' -TimeoutSeconds 60)
            @(foreach ($t in $rows) {
                $dir = 0; try { $dir = [int]"$($t['trustDirection'])" } catch { }
                $typ = 0; try { $typ = [int]"$($t['trustType'])" } catch { }
                $att = 0; try { $att = [int]"$($t['trustAttributes'])" } catch { }
                [ordered]@{
                    Target        = Protect-Hostname -Value "$($t['name'])"
                    Direction     = switch ($dir) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { "Unknown($dir)" } }
                    Type          = switch ($typ) { 1 { 'Downlevel (NT)' } 2 { 'Uplevel (AD)' } 3 { 'MIT Kerberos' } 4 { 'DCE' } default { "Unknown($typ)" } }
                    IsForestTrust = (($att -band 8) -ne 0)
                    IsIntraForest = (($att -band 0x20) -ne 0)
                    IsTransitive  = (($att -band 1) -eq 0)
                    SelectiveAuth = (($att -band 0x10) -ne 0)
                }
            })
        }
        $out.TrustCount = Get-SafeCount -Value $out.Trusts

        $out.Schema = Invoke-Guarded -What 'Schema versions' -Script {
            $schemaObj = [ADSI]("LDAP://" + $script:Ctx.SchemaNC)
            $adSchemaVersion = Get-AdsiPropertyValue -Entry $schemaObj -Name 'objectVersion'
            $adName = switch ([int]$adSchemaVersion) {
                13 { 'Windows 2000' } 30 { 'Windows Server 2003' } 31 { 'Windows Server 2003 R2' } 44 { 'Windows Server 2008' }
                47 { 'Windows Server 2008 R2' } 56 { 'Windows Server 2012' } 69 { 'Windows Server 2012 R2' } 87 { 'Windows Server 2016' }
                88 { 'Windows Server 2019 / 2022' } 91 { 'Windows Server 2025' } default { "Unknown ($adSchemaVersion)" }
            }
            $exSchema = 0
            try {
                $exObj = [ADSI]("LDAP://CN=ms-Exch-Schema-Version-Pt," + $script:Ctx.SchemaNC)
                $exSchema = [int](Get-AdsiPropertyValue -Entry $exObj -Name 'rangeUpper')
            }
            catch { $exSchema = 0 }
            [ordered]@{
                ActiveDirectorySchemaVersion = $adSchemaVersion
                ActiveDirectorySchemaName    = $adName
                ExchangeSchemaPresent        = ($exSchema -gt 0)
                ExchangeSchemaRangeUpper     = $exSchema
                ExchangeSchemaName           = Get-ExchangeSchemaVersionName -RangeUpper $exSchema
            }
        }
    }

    $out.DnsServersOnThisHost = Invoke-Guarded -What 'DNS servers' -Script {
        $dns = @()
        if (Get-Command -Name 'Get-DnsClientServerAddress' -ErrorAction SilentlyContinue) {
            foreach ($i in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)) {
                if ($i.ServerAddresses.Count -gt 0) { $dns += [ordered]@{ Interface = $i.InterfaceAlias; Servers = @($i.ServerAddresses) } }
            }
        }
        else {
            foreach ($n in @(Get-CimSafe -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE')) {
                if ($n.DNSServerSearchOrder) { $dns += [ordered]@{ Interface = $n.Description; Servers = @($n.DNSServerSearchOrder) } }
            }
        }
        ,$dns
    }

    return $out
}

# =======================================================================================
# SECTION C (part 1) - Exchange detection WITHOUT Exchange tools: registry + AD
# Runs before the tools loader so that it always produces something.
# =======================================================================================
function Get-ExchangeDetectionSection {
    $out = [ordered]@{}

    # --- Registry -----------------------------------------------------------------------
    $reg = [ordered]@{}
    foreach ($key in @('v14', 'v15')) {
        $setupPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$key\Setup"
        if (Test-Path -LiteralPath $setupPath) {
            $major = Get-RegistryValue -Path $setupPath -Name 'MsiProductMajor'
            $minor = Get-RegistryValue -Path $setupPath -Name 'MsiProductMinor'
            $bMaj  = Get-RegistryValue -Path $setupPath -Name 'MsiBuildMajor'
            $bMin  = Get-RegistryValue -Path $setupPath -Name 'MsiBuildMinor'
            $inst  = Get-RegistryValue -Path $setupPath -Name 'MsiInstallPath'
            $friendly = $null
            if ($null -ne $major) { $friendly = Get-ExchangeProductName -Major ([int]$major) -Minor ([int]$minor) -Build ([int]$bMaj) }
            $roles = [ordered]@{}
            foreach ($sub in @(Get-RegistryKeyNames -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$key")) {
                if ($sub -match 'Role$|^AdminTools$|^Hygiene|^Language') {
                    $rp = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$key\$sub"
                    $roles[$sub] = [ordered]@{
                        ConfiguredVersion = Get-RegistryValue -Path $rp -Name 'ConfiguredVersion'
                        UnpackedVersion   = Get-RegistryValue -Path $rp -Name 'UnpackedVersion'
                        Action            = Get-RegistryValue -Path $rp -Name 'Action'
                        WatermarkPresent  = ($null -ne (Get-RegistryValue -Path $rp -Name 'Watermark'))
                    }
                }
            }
            $reg[$key] = [ordered]@{
                Present          = $true
                MsiProductMajor  = $major
                MsiProductMinor  = $minor
                MsiBuildMajor    = $bMaj
                MsiBuildMinor    = $bMin
                VersionString    = $(if ($null -ne $major) { '{0}.{1}.{2}.{3}' -f $major, $minor, $bMaj, $bMin } else { $null })
                FriendlyName     = $friendly
                MsiInstallPath   = Protect-FilePath -Value "$inst"
                Services         = Get-RegistryValue -Path $setupPath -Name 'Services'
                RoleKeys         = $roles
            }
            if ($null -ne $major) {
                $script:Ctx.ExchangeInstalled   = $true
                $script:Ctx.ExchangeVersionKey  = $key
                $script:Ctx.ExchangeProduct     = $friendly
                $script:Ctx.ExchangeInstallPath = $inst
                $script:Ctx.ExchangeVersionString = $reg[$key].VersionString
            }
        }
        else { $reg[$key] = [ordered]@{ Present = $false } }
    }
    $out.Registry = $reg
    $out.ExchangeInstallPathEnv = Protect-FilePath -Value "$env:ExchangeInstallPath"

    # --- ExSetup.exe file version (most precise build) ----------------------------------
    $out.ExSetupFileVersion = Invoke-Guarded -What 'ExSetup version' -Script {
        $p = $script:Ctx.ExchangeInstallPath
        if (-not $p -and $env:ExchangeInstallPath) { $p = $env:ExchangeInstallPath }
        if ($p) {
            $exe = Join-Path $p 'bin\ExSetup.exe'
            if (Test-Path -LiteralPath $exe) {
                $vi = (Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo
                $fv = "$($vi.FileVersion)"
                $friendly = ConvertFrom-ExchangeVersionString -Text $fv
                if ($friendly) { $script:Ctx.ExchangeProduct = $friendly; $script:Ctx.ExchangeVersionString = $fv }
                return ([ordered]@{ Path = (Protect-FilePath -Value $exe); FileVersion = $fv; ProductVersion = "$($vi.ProductVersion)"; FriendlyName = $friendly })
            }
        }
        return $null
    }

    # --- Active Directory: Exchange organisation, schema, servers -----------------------
    if ($script:Ctx.IsDomainJoined -and $script:Ctx.ConfigNC) {
        $cfg = $script:Ctx.ConfigNC
        $out.ActiveDirectory = Invoke-Guarded -What 'Exchange org from AD' -Script {
            $ad = [ordered]@{}
            $orgs = @(Search-Directory -SearchBase ("LDAP://CN=Microsoft Exchange,CN=Services," + $cfg) -Filter '(objectClass=msExchOrganizationContainer)' -Properties @('name', 'objectVersion', 'msExchProductId', 'msExchVersion', 'whenCreated', 'distinguishedName') -Scope 'OneLevel')
            $ad.OrganizationPresent = ($orgs.Count -gt 0)
            if ($orgs.Count -gt 0) {
                $org = $orgs[0]
                $script:Ctx.ExchangeOrgDn = "$($org.distinguishedName)"
                $ad.OrganizationName    = Protect-Hostname -Value "$($org.name)"
                # Must be stringified like its siblings. Left as a live ADSI property collection this
                # holds a reference back to its parent entry, which made ConvertTo-Json throw on the
                # whole ExchangeDetection section (King Springs, 15 Sep 2026).
                $ad.OrgObjectVersion    = "$($org.objectVersion)"
                $ad.OrgProductId        = "$($org.msExchProductId)"
                $ad.OrgMsExchVersion    = "$($org.msExchVersion)"
                $ad.OrgCreated          = ConvertTo-IsoString -Value $org.whenCreated

                $servers = @(Search-Directory -SearchBase ("LDAP://" + $org.distinguishedName) -Filter '(objectClass=msExchExchangeServer)' -Properties @('name', 'serialNumber', 'versionNumber', 'msExchCurrentServerRoles', 'msExchServerSite', 'msExchInstallPath', 'msExchProductID', 'whenCreated', 'networkAddress', 'msExchEdgeSyncLease') -Scope 'Subtree' -TimeoutSeconds 60)
                $ad.ServerCount = $servers.Count
                $ad.Servers = @(foreach ($s in $servers) {
                    $roleMask = 0
                    try { $roleMask = [long]$s.msExchCurrentServerRoles } catch { }
                    $ver = ConvertTo-ExchangeVersion -Text "$($s.serialNumber)"
                    [ordered]@{
                        Name          = Protect-Hostname -Value "$($s.name)"
                        IsLocalMachine = ("$($s.name)" -ieq $env:COMPUTERNAME)
                        SerialNumber  = "$($s.serialNumber)"
                        FriendlyVersion = ConvertFrom-ExchangeVersionString -Text "$($s.serialNumber)"
                        Version       = $(if ($ver) { "$ver" } else { $null })
                        Family        = Get-ExchangeFamilyFromVersion -Version $ver
                        VersionNumber = $s.versionNumber
                        RoleMask      = $roleMask
                        Roles         = ConvertFrom-ServerRoleMask -Mask $roleMask
                        IsEdge        = (($roleMask -band 64) -ne 0)
                        Site          = Protect-Hostname -Value (Get-DnFirstComponent -Dn "$($s.msExchServerSite)")
                        InstallPath   = Protect-FilePath -Value "$($s.msExchInstallPath)"
                        ProductId     = "$($s.msExchProductID)"
                        Created       = ConvertTo-IsoString -Value $s.whenCreated
                    }
                })
                # Org-wide version span (finding 35): decisions about support and coexistence
                # are made from the OLDEST server in the org, not from the local host.
                $minVer = $null; $maxVer = $null; $minSrv = $null; $maxSrv = $null; $families = @{}
                foreach ($s in $ad.Servers) {
                    $v = ConvertTo-ExchangeVersion -Text $s.SerialNumber
                    if ($null -eq $v) { continue }
                    if ($s.Family) { if (-not $families.ContainsKey($s.Family)) { $families[$s.Family] = 0 }; $families[$s.Family] = $families[$s.Family] + 1 }
                    if ($null -eq $minVer -or $v -lt $minVer) { $minVer = $v; $minSrv = $s }
                    if ($null -eq $maxVer -or $v -gt $maxVer) { $maxVer = $v; $maxSrv = $s }
                }
                $ad.OrgMinVersion = $(if ($minVer) { "$minVer" } else { $null })
                $ad.OrgMinVersionProduct = $(if ($minSrv) { $minSrv.FriendlyVersion } else { $null })
                $ad.OrgMaxVersion = $(if ($maxVer) { "$maxVer" } else { $null })
                $ad.OrgMaxVersionProduct = $(if ($maxSrv) { $maxSrv.FriendlyVersion } else { $null })
                $famOrdered = [ordered]@{}; foreach ($k in ($families.Keys | Sort-Object)) { $famOrdered[$k] = $families[$k] }
                $ad.ServerCountByFamily = $famOrdered
                $ad.IsMixedVersionOrg = ($families.Count -gt 1)
                $script:Ctx.OrgMinVersion = $minVer
                $script:Ctx.OrgMaxVersion = $maxVer
                $script:Ctx.OrgMinProduct = $ad.OrgMinVersionProduct
                $script:Ctx.OrgMaxProduct = $ad.OrgMaxVersionProduct
                $script:Ctx.OrgMinFamily  = Get-ExchangeFamilyFromVersion -Version $minVer
                $script:Ctx.OrgMaxFamily  = Get-ExchangeFamilyFromVersion -Version $maxVer
                $script:Ctx.OrgServerCount = $servers.Count
                $script:Ctx.OrgServerCountByFamily = $famOrdered

                # Note: the authoritative single-server override lives in Get-SummarySection, not
                # here. This section runs BEFORE Exchange detection, so $Ctx.ExchangeProduct is
                # still null at this point.
                $local = @($ad.Servers | Where-Object { $_.IsLocalMachine })
                $script:Ctx.LocalServerInAd = ($local.Count -gt 0)
                $script:Ctx.LocalServerAdRoleMask = $(if ($local.Count -gt 0) { [long]$local[0].RoleMask } else { 0 })
            }
            # Exchange containers per domain (objectVersion on 'Microsoft Exchange System Objects')
            $ad.DomainExchangeContainers = @()
            try {
                $domainNcs = @($script:Ctx.DefaultNC)
                if ($script:Ctx.RootDomainNC -and $script:Ctx.RootDomainNC -ne $script:Ctx.DefaultNC) { $domainNcs += $script:Ctx.RootDomainNC }
                foreach ($nc in $domainNcs) {
                    try {
                        $meso = [ADSI]("LDAP://CN=Microsoft Exchange System Objects," + $nc)
                        $ad.DomainExchangeContainers += [ordered]@{ Domain = (Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $nc)); ObjectVersion = (Get-AdsiPropertyValue -Entry $meso -Name 'objectVersion') }
                    }
                    catch { $ad.DomainExchangeContainers += [ordered]@{ Domain = (Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $nc)); ObjectVersion = $null; Note = 'container not found' } }
                }
            }
            catch { }
            $ad
        }
    }
    else {
        $out.ActiveDirectory = [ordered]@{ Note = 'Not domain-joined or configuration naming context unavailable; AD-based Exchange discovery skipped.' }
    }

    if (-not $script:Ctx.ExchangeInstalled -and $script:Ctx.OrgMaxProduct) {
        # No local install; report the NEWEST server in AD as the product (the org span is
        # reported separately and the oldest server drives the blockers).
        $script:Ctx.ExchangeProduct = "$($script:Ctx.OrgMaxProduct) (newest server in AD; not installed locally)"
        if ($script:Ctx.OrgMaxVersion) { $script:Ctx.ExchangeVersionString = "$($script:Ctx.OrgMaxVersion)" }
    }
    $out.DetectedProduct = $script:Ctx.ExchangeProduct
    $out.OrgMinVersionProduct = $script:Ctx.OrgMinProduct
    $out.OrgMaxVersionProduct = $script:Ctx.OrgMaxProduct

    # --- Management-tools-only determination (finding 37) ---------------------------------
    # Keyed on the presence of a *Role key with a ConfiguredVersion (never on Action, which
    # varies between RTM, CU-updated and repaired installs), cross-checked against the AD
    # server object for this host and the core Exchange services.
    $toolsOnly = $false
    $evidence = [ordered]@{ AdminToolsKeyPresent = $false; RoleKeysWithConfiguredVersion = @(); CoreServicesPresent = @(); AdServerObjectForThisHost = $false; AdRoleMaskForThisHost = 0 }
    if ($script:Ctx.ExchangeVersionKey) {
        $rk = $reg[$script:Ctx.ExchangeVersionKey].RoleKeys
        $evidence.AdminToolsKeyPresent = [bool]$rk.Contains('AdminTools')
        $roleKeys = @()
        foreach ($k in $rk.Keys) { if ($k -match 'Role$' -and $rk[$k].ConfiguredVersion) { $roleKeys += $k } }
        $evidence.RoleKeysWithConfiguredVersion = $roleKeys
        $core = @()
        foreach ($svc in @(Get-CimSafe -Class 'Win32_Service' -Filter "Name='MSExchangeIS' OR Name='MSExchangeTransport' OR Name='MSExchangeFrontEndTransport' OR Name='MSExchangeMailboxAssistants' OR Name='MSExchangeRPC' OR Name='MSExchangeServiceHost'")) { $core += "$($svc.Name)" }
        $evidence.CoreServicesPresent = $core
        $evidence.AdServerObjectForThisHost = [bool]$script:Ctx.LocalServerInAd
        $evidence.AdRoleMaskForThisHost = $script:Ctx.LocalServerAdRoleMask
        $adHasRole = ($script:Ctx.LocalServerAdRoleMask -band (2 + 4 + 16 + 32 + 64 + 16384)) -ne 0
        $toolsOnly = ($evidence.AdminToolsKeyPresent -and $roleKeys.Count -eq 0 -and $core.Count -eq 0 -and -not $adHasRole)
        if ($evidence.AdminToolsKeyPresent -and $roleKeys.Count -eq 0 -and ($core.Count -gt 0 -or $adHasRole)) {
            Write-SectionWarning -Message 'Registry shows no role key but Exchange services or an AD server role exist for this host; treating it as a full server, not management-tools-only.'
        }
    }
    $out.ManagementToolsOnlyInstall = $toolsOnly
    $out.ManagementToolsOnlyEvidence = $evidence
    $script:Ctx.ManagementToolsOnly = $toolsOnly
    return $out
}

# =======================================================================================
# Certificate issuer handling and management-interface evidence helpers
# =======================================================================================
$script:PublicCaPattern = '(?i)DigiCert|Let''s Encrypt|ISRG|^(R|E)\d{1,2}$|Sectigo|Comodo|GlobalSign|GoDaddy|Go Daddy|Starfield|Entrust|Thawte|GeoTrust|RapidSSL|Symantec|VeriSign|Amazon|Google Trust|Microsoft (RSA|ECC|Azure|IT|Secure)|Buypass|ZeroSSL|SSL\.com|Actalis|Certum|IdenTrust|DST Root|USERTrust|Network Solutions|Trustwave|QuoVadis|SwissSign|Baltimore|Cybertrust|AddTrust|Encryption Everywhere|cPanel|Cloudflare|Gandi|Namecheap|PositiveSSL|Positive SSL|InCommon|TrustAsia|WoTrus|Telia|D-Trust|HARICA|SecureTrust|Atos|Certigna'

function Test-PublicCertificateAuthority {
    param([string]$IssuerCN)
    if ([string]::IsNullOrWhiteSpace($IssuerCN)) { return $false }
    return [bool]($IssuerCN -match $script:PublicCaPattern)
}

function Protect-CertificateIssuer {
    # Public CA names are product identifiers and stay in clear. DNS-shaped issuer names go
    # through Protect-Hostname like subjects. Anything else (an internal CA name usually embeds
    # the organisation or a server name) is hashed.
    param([string]$IssuerCN)
    if ([string]::IsNullOrWhiteSpace($IssuerCN)) { return $null }
    if (Test-PublicCertificateAuthority -IssuerCN $IssuerCN) { return $IssuerCN }
    if ($IssuerCN -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { return (Protect-Hostname -Value $IssuerCN) }
    return (Protect-Identifier -Value $IssuerCN)
}

function Test-ServerAuthenticationCertificate {
    # True for certificates usable for TLS server authentication (EKU 1.3.6.1.5.5.7.3.1 or no
    # EKU restriction). Excludes S/MIME (1.3.6.1.5.5.7.3.4), client-auth-only, code-signing and
    # smart-card certificates, so the no-tools fallback does not enumerate personal certs.
    param($Certificate)
    try {
        $ekus = @()
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                foreach ($oid in $ext.EnhancedKeyUsages) { $ekus += "$($oid.Value)" }
            }
        }
        if ($ekus.Count -eq 0) { return $true }
        return ($ekus -contains '1.3.6.1.5.5.7.3.1')
    }
    catch { return $false }
}

function ConvertTo-GigabytesFromSizeText {
    # Exchange ByteQuantifiedSize text: '12.5 GB (13,421,772,800 bytes)' -> 12.5
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        if ($Text -match '\(([\d,]+)\s+bytes\)') { return [math]::Round(([double]($Matches[1] -replace ',', '')) / 1GB, 2) }
        if ($Text -match '^([\d.]+)\s*(B|KB|MB|GB|TB)') {
            $n = [double]$Matches[1]
            switch ($Matches[2]) { 'B' { return [math]::Round($n / 1GB, 2) } 'KB' { return [math]::Round($n / 1MB, 2) } 'MB' { return [math]::Round($n / 1KB, 2) } 'GB' { return [math]::Round($n, 2) } 'TB' { return [math]::Round($n * 1024, 2) } }
        }
    }
    catch { }
    return $null
}

function Get-LogFolderActivity {
    # File METADATA only (count, newest write, files written in the last 30 days, size). No log
    # content is read. Used to see whether an Exchange logging folder is active at all.
    param([string]$Path, [string]$Pattern = '*.log')
    if ([string]::IsNullOrWhiteSpace($Path)) { return ([ordered]@{ Present = $false }) }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return ([ordered]@{ Present = $false }) }
        $files = @([System.IO.Directory]::GetFiles($Path, $Pattern))
        $count = 0; $newest = $null; $recent = 0; $bytes = [long]0
        $cut = (Get-Date).AddDays(-30)
        foreach ($f in $files) {
            try {
                $fi = New-Object System.IO.FileInfo($f)
                $count++; $bytes += $fi.Length
                if ($null -eq $newest -or $fi.LastWriteTime -gt $newest) { $newest = $fi.LastWriteTime }
                if ($fi.LastWriteTime -gt $cut) { $recent++ }
            }
            catch { }
            if ($count -ge 10000) { break }
        }
        return ([ordered]@{ Present = $true; FileCount = $count; FilesWrittenLast30Days = $recent; NewestWrite = (ConvertTo-IsoString -Value $newest); TotalMB = [math]::Round($bytes / 1MB, 1) })
    }
    catch { return ([ordered]@{ Present = $null; Error = (ConvertTo-SafeError -ErrorRecord $_) }) }
}

function Get-ManagementInterfaceEvidence {
    # Finding 33. Measured evidence of HOW this server is administered, reported separately
    # from the version-inferred guess. Nothing here needs Exchange cmdlets.
    $ev = [ordered]@{}
    $ip = $script:Ctx.ExchangeInstallPath
    if (-not $ip -and $env:ExchangeInstallPath) { $ip = $env:ExchangeInstallPath }

    # 1. Console artefacts on disk: the 2010 EMC ships 'Exchange Management Console.msc'; 2013+
    #    ships 'Exchange Toolbox.msc' and no MMC console; the standalone tools role ships no ECP.
    $ev.ConsoleArtefacts = Invoke-Guarded -What 'Console artefacts' -Script {
        $a = [ordered]@{ InstallPathKnown = [bool]$ip }
        if ($ip) {
            $a.ExchangeManagementConsoleMsc_2010 = Test-Path -LiteralPath (Join-Path $ip 'Bin\Exchange Management Console.msc')
            $a.EmcSnapInDll_2010                 = Test-Path -LiteralPath (Join-Path $ip 'Bin\Microsoft.Exchange.Management.SnapIn.Esm.dll')
            $a.ExchangeToolboxMsc_2013Plus       = Test-Path -LiteralPath (Join-Path $ip 'Bin\Exchange Toolbox.msc')
            $a.RemoteExchangePs1                 = Test-Path -LiteralPath (Join-Path $ip 'Bin\RemoteExchange.ps1')
            $a.ClientAccessEcpFolder             = Test-Path -LiteralPath (Join-Path $ip 'ClientAccess\ecp')
            $a.FrontEndEcpFolder                 = Test-Path -LiteralPath (Join-Path $ip 'FrontEnd\HttpProxy\ecp')
            $a.ClientAccessPowerShellFolder      = Test-Path -LiteralPath (Join-Path $ip 'ClientAccess\PowerShell')
        }
        $sm = $null
        if ($env:ProgramData) { $sm = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs' }
        if ($sm -and (Test-Path -LiteralPath $sm)) {
            $lnk = @(Get-ChildItem -LiteralPath $sm -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^Exchange (Management Console|Management Shell|Toolbox)' } | ForEach-Object { $_.Name })
            $a.StartMenu_ExchangeManagementConsole = [bool]($lnk -match '(?i)Management Console')
            $a.StartMenu_ExchangeManagementShell   = [bool]($lnk -match '(?i)Management Shell')
            $a.StartMenu_ExchangeToolbox           = [bool]($lnk -match '(?i)Toolbox')
        }
        $a
    }

    # 2. 'MSExchange Management' event log: every cmdlet run through the Exchange management
    #    plane on this host is logged here (2010 and 2013+). Only the cmdlet NAME token and, when
    #    present, the ClientApplication token are taken from each message; parameter values are
    #    never read. Newest 5,000 events.
    $ev.ManagementEventLog = Invoke-Guarded -What 'MSExchange Management event log' -Script {
        $present = $false
        try { $present = [bool](Get-WinEvent -ListLog 'MSExchange Management' -ErrorAction Stop) } catch { $present = $false }
        if (-not $present) { return ([ordered]@{ Present = $false }) }
        $events = @(Get-WinEvent -LogName 'MSExchange Management' -MaxEvents 5000 -ErrorAction Stop)
        $byCmdlet = @{}; $byClient = @{}; $byId = @{}; $newest = $null; $oldest = $null; $n = 0
        $cut30 = (Get-Date).AddDays(-30); $last30 = 0; $mutating30 = 0
        foreach ($e in $events) {
            $n++
            if (($n % 500) -eq 0) { Assert-Deadline }
            $t = $e.TimeCreated
            if ($null -eq $newest -or $t -gt $newest) { $newest = $t }
            if ($null -eq $oldest -or $t -lt $oldest) { $oldest = $t }
            $id = "$($e.Id)"; if (-not $byId.ContainsKey($id)) { $byId[$id] = 0 }; $byId[$id] = $byId[$id] + 1
            $msg = ''; try { $msg = "$($e.Message)" } catch { $msg = '' }
            $cmd = $null
            if ($msg -match '(?i)\bCmdlet\s+(?<c>[A-Za-z]+-[A-Za-z0-9]+)') { $cmd = $Matches['c'] }
            if ($cmd) {
                if (-not $byCmdlet.ContainsKey($cmd)) { $byCmdlet[$cmd] = 0 }; $byCmdlet[$cmd] = $byCmdlet[$cmd] + 1
                if ($t -gt $cut30) { $last30++; if ($cmd -notmatch '^(Get|Test|Search|Export)-') { $mutating30++ } }
            }
            if ($msg -match '(?i)ClientApplication\s*[=:]\s*(?<a>[A-Za-z0-9_.-]{1,40})') { $ca = $Matches['a']; if (-not $byClient.ContainsKey($ca)) { $byClient[$ca] = 0 }; $byClient[$ca] = $byClient[$ca] + 1 }
        }
        $top = [ordered]@{}
        foreach ($k in ($byCmdlet.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 25)) { $top[$k.Key] = $k.Value }
        $clients = [ordered]@{}; foreach ($k in ($byClient.Keys | Sort-Object)) { $clients[$k] = $byClient[$k] }
        $ids = [ordered]@{}; foreach ($k in ($byId.Keys | Sort-Object)) { $ids[$k] = $byId[$k] }
        [ordered]@{
            Present                  = $true
            EventsSampled            = $n
            SampleCapReached         = ($n -ge 5000)
            OldestSampled            = ConvertTo-IsoString -Value $oldest
            NewestSampled            = ConvertTo-IsoString -Value $newest
            CmdletEventsLast30Days   = $last30
            NonReadCmdletEventsLast30Days = $mutating30
            ByEventId                = $ids
            ByClientApplication      = $clients
            TopCmdlets               = $top
            Note                     = 'Cmdlet names and ClientApplication tokens only; no parameters, identities or message text are read.'
        }
    }

    # 3. Exchange logging folders (2013+): file metadata only. HttpProxy\Ecp and CmdletInfra\Ecp
    #    show whether the ECP/EAC pipeline is active; note that Managed Availability probes also
    #    hit /ecp, so this is corroborating evidence, not proof of human use (see the IIS sample).
    $ev.LogFolders = Invoke-Guarded -What 'Exchange logging folders' -Script {
        $l = [ordered]@{ InstallPathKnown = [bool]$ip }
        if ($ip) {
            $l.CmdletInfra_Ecp             = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\CmdletInfra\Ecp\Cmdlet')
            $l.CmdletInfra_PowerShellProxy = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\CmdletInfra\Powershell-Proxy\Cmdlet')
            $l.CmdletInfra_Others          = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\CmdletInfra\Others\Cmdlet')
            $l.HttpProxy_Ecp               = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\HttpProxy\Ecp')
            $l.HttpProxy_PowerShell        = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\HttpProxy\PowerShell')
            $l.HttpProxy_Owa               = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\HttpProxy\Owa')
            $l.Ecp_Server                  = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\ECP\Server')
            $l.Ecp_Activity                = Get-LogFolderActivity -Path (Join-Path $ip 'Logging\ECP\Activity')
            $l.MessageTracking             = Get-LogFolderActivity -Path (Join-Path $ip 'TransportRoles\Logs\MessageTracking')
            $l.FrontEndProtocolSmtpReceive = Get-LogFolderActivity -Path (Join-Path $ip 'TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive')
            $l.HubProtocolSmtpReceive      = Get-LogFolderActivity -Path (Join-Path $ip 'TransportRoles\Logs\Hub\ProtocolLog\SmtpReceive')
            $l.ProtocolSmtpReceive_2010    = Get-LogFolderActivity -Path (Join-Path $ip 'TransportRoles\Logs\ProtocolLog\SmtpReceive')
        }
        $l
    }

    # 4. IIS log sample for the Default Web Site (W3SVC1): request COUNTS by Exchange endpoint,
    #    with Managed Availability probe traffic excluded, plus the clientApplication token of
    #    remote PowerShell connections. Fields read: cs-uri-stem, cs-uri-query, cs-username,
    #    cs(User-Agent). No username, client IP, query value or line ever leaves this block; the
    #    distinct-user figure is computed from an in-memory set and only its count is kept.
    $ev.IisLogSample = Invoke-Guarded -What 'IIS log sample' -Script {
        $logRoot = $null
        foreach ($cand in @((Join-Path $env:SystemDrive 'inetpub\logs\LogFiles\W3SVC1'), (Join-Path $env:windir 'System32\LogFiles\W3SVC1'))) {
            if (Test-Path -LiteralPath $cand) { $logRoot = $cand; break }
        }
        if (-not $logRoot) { return ([ordered]@{ Present = $false; Note = 'IIS log folder for site 1 (Default Web Site) not found at the default locations.' }) }
        $files = @(Get-ChildItem -LiteralPath $logRoot -Filter '*.log' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
        if ($files.Count -eq 0) { return ([ordered]@{ Present = $true; FilesScanned = 0; Note = 'No IIS log files present.' }) }
        $lineCap = 300000; $lines = 0; $truncated = $false
        $c = [ordered]@{ Ecp = 0; EcpProbe = 0; Owa = 0; OwaProbe = 0; PowerShell = 0; PowerShellProbe = 0; Ews = 0; Mapi = 0; ActiveSync = 0; Autodiscover = 0; Oab = 0; Rpc = 0; Other = 0 }
        $psClients = @{}
        $ecpUsers = New-Object System.Collections.Generic.HashSet[string]
        $psUsers  = New-Object System.Collections.Generic.HashSet[string]
        $firstTs = $null; $lastTs = $null
        foreach ($f in $files) {
            $sr = $null
            $fs = $null
            try {
                # IIS keeps the current log open for writing, so the default StreamReader share mode
                # (FileShare.Read) throws IOException on the newest file - which is the one we most want.
                # Open with FileShare.ReadWrite | Delete so we can read a live log. Verified against a
                # King Springs Exchange 2016 server, 15 Sep 2026, where the default mode failed.
                $fsShare = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
                $fs = New-Object System.IO.FileStream($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $fsShare)
                $sr = New-Object System.IO.StreamReader($fs)
                $iStem = -1; $iQuery = -1; $iUser = -1; $iUa = -1; $iDate = -1; $iTime = -1
                while ($null -ne ($line = $sr.ReadLine())) {
                    $lines++
                    if ($lines -gt $lineCap) { $truncated = $true; break }
                    if (($lines % 20000) -eq 0) { Assert-Deadline }
                    if ($line.Length -eq 0) { continue }
                    if ($line[0] -eq '#') {
                        if ($line.StartsWith('#Fields:')) {
                            $fields = @($line.Substring(8).Trim() -split '\s+')
                            $iStem = [array]::IndexOf($fields, 'cs-uri-stem'); $iQuery = [array]::IndexOf($fields, 'cs-uri-query')
                            $iUser = [array]::IndexOf($fields, 'cs-username'); $iUa = [array]::IndexOf($fields, 'cs(User-Agent)')
                            $iDate = [array]::IndexOf($fields, 'date'); $iTime = [array]::IndexOf($fields, 'time')
                        }
                        continue
                    }
                    if ($iStem -lt 0) { continue }
                    $parts = $line.Split(' ')
                    if ($parts.Length -le $iStem) { continue }
                    $stem = $parts[$iStem].ToLowerInvariant()
                    $user = $(if ($iUser -ge 0 -and $parts.Length -gt $iUser) { $parts[$iUser] } else { '-' })
                    $ua   = $(if ($iUa -ge 0 -and $parts.Length -gt $iUa) { $parts[$iUa] } else { '' })
                    $qry  = $(if ($iQuery -ge 0 -and $parts.Length -gt $iQuery) { $parts[$iQuery] } else { '' })
                    if ($iDate -ge 0 -and $iTime -ge 0 -and $parts.Length -gt $iTime) {
                        $ts = $parts[$iDate] + 'T' + $parts[$iTime]
                        if ($null -eq $firstTs -or $ts -lt $firstTs) { $firstTs = $ts }
                        if ($null -eq $lastTs -or $ts -gt $lastTs) { $lastTs = $ts }
                    }
                    $isProbe = ($user -match '(?i)healthmailbox' -or $ua -match '(?i)AMProbe|MSExchangeMonitoring|ExchangeHealth|Exchange Health Manager|MonitoringProbe')
                    $bucket = 'Other'
                    if ($stem.StartsWith('/ecp')) { $bucket = $(if ($isProbe) { 'EcpProbe' } else { 'Ecp' }); if (-not $isProbe -and $user -ne '-') { [void]$ecpUsers.Add($user.ToLowerInvariant()) } }
                    elseif ($stem.StartsWith('/owa')) { $bucket = $(if ($isProbe) { 'OwaProbe' } else { 'Owa' }) }
                    elseif ($stem.StartsWith('/powershell')) {
                        $bucket = $(if ($isProbe) { 'PowerShellProbe' } else { 'PowerShell' })
                        if (-not $isProbe) {
                            if ($user -ne '-') { [void]$psUsers.Add($user.ToLowerInvariant()) }
                            if ($qry -match '(?i)clientApplication=(?<a>[A-Za-z0-9_.-]{1,40})') { $ca = $Matches['a']; if (-not $psClients.ContainsKey($ca)) { $psClients[$ca] = 0 }; $psClients[$ca] = $psClients[$ca] + 1 }
                        }
                    }
                    elseif ($stem.StartsWith('/ews')) { $bucket = 'Ews' }
                    elseif ($stem.StartsWith('/mapi')) { $bucket = 'Mapi' }
                    elseif ($stem.StartsWith('/microsoft-server-activesync')) { $bucket = 'ActiveSync' }
                    elseif ($stem.StartsWith('/autodiscover')) { $bucket = 'Autodiscover' }
                    elseif ($stem.StartsWith('/oab')) { $bucket = 'Oab' }
                    elseif ($stem.StartsWith('/rpc')) { $bucket = 'Rpc' }
                    $c[$bucket] = $c[$bucket] + 1
                }
            }
            finally {
                if ($null -ne $sr) { try { $sr.Dispose() } catch { } }
                if ($null -ne $fs) { try { $fs.Dispose() } catch { } }
                $fs = $null
            }
            if ($truncated) { break }
        }
        $clients = [ordered]@{}; foreach ($k in ($psClients.Keys | Sort-Object)) { $clients[$k] = $psClients[$k] }
        [ordered]@{
            Present            = $true
            FilesScanned       = $files.Count
            LinesScanned       = $lines
            TruncatedAtLineCap = $truncated
            SampleFrom         = $firstTs
            SampleTo           = $lastTs
            RequestsByEndpoint = $c
            EcpDistinctNonProbeUsers        = $ecpUsers.Count
            PowerShellDistinctNonProbeUsers = $psUsers.Count
            PowerShellByClientApplication   = $clients
            Note = 'Counts only. Health-probe traffic (HealthMailbox accounts, AMProbe/monitoring user agents) is excluded from the non-probe figures.'
        }
    }

    # 5. Operator traces on this host: MMC recent-file list of the account running the script
    #    (boolean only) and Prefetch (usually disabled on servers).
    $ev.OperatorTraces = Invoke-Guarded -What 'Operator MMC/Prefetch traces' -Script {
        $t = [ordered]@{}
        $hits = 0
        try {
            $key = 'HKCU:\Software\Microsoft\Microsoft Management Console\Recent File List'
            if (Test-Path -LiteralPath $key) {
                $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) { if ($p.Name -like 'File*' -and "$($p.Value)" -match '(?i)Exchange (Management Console|Toolbox)\.msc') { $hits++ } }
            }
        }
        catch { }
        $t.OperatorMmcRecentListIncludesExchangeConsole = ($hits -gt 0)
        $pf = Join-Path $env:windir 'Prefetch'
        $pfFiles = @(); if (Test-Path -LiteralPath $pf) { $pfFiles = @(Get-ChildItem -LiteralPath $pf -Filter '*.pf' -ErrorAction SilentlyContinue) }
        $t.PrefetchActive = ($pfFiles.Count -gt 0)
        $mmc = @($pfFiles | Where-Object { $_.Name -like 'MMC.EXE-*' } | Sort-Object LastWriteTime -Descending)
        $ps  = @($pfFiles | Where-Object { $_.Name -like 'POWERSHELL.EXE-*' } | Sort-Object LastWriteTime -Descending)
        $t.MmcPrefetchLastWrite        = $(if ($mmc.Count -gt 0) { ConvertTo-IsoString -Value $mmc[0].LastWriteTime } else { $null })
        $t.PowerShellPrefetchLastWrite = $(if ($ps.Count -gt 0) { ConvertTo-IsoString -Value $ps[0].LastWriteTime } else { $null })
        $t
    }

    # 6. Conclusion from the evidence above (observed), kept separate from the version guess.
    $obs = @()
    try {
        $ca = $ev.ConsoleArtefacts
        if ($ca -is [System.Collections.IDictionary]) {
            # The .msc file is the only reliable 2010 EMC marker. Microsoft.Exchange.Management.SnapIn.Esm.dll
            # also ships on 2013+ (verified on an Exchange 2016 CU23 server, 15 Sep 2026), so it must never
            # on its own assert that the 2010 console is installed - that is the question this engagement
            # turns on and a false positive there is worse than no answer.
            if ($ca['ExchangeManagementConsoleMsc_2010'] -eq $true) { $obs += 'Exchange Management Console (MMC, 2010) is installed on this host' }
            elseif ($ca['EmcSnapInDll_2010'] -eq $true) { $obs += 'Legacy EMC snap-in assembly present, but no Exchange Management Console .msc - this assembly also ships on Exchange 2013 and later, so it is NOT evidence of the 2010 console' }
            if ($ca['ExchangeToolboxMsc_2013Plus'] -eq $true) { $obs += 'Exchange Toolbox (2013+) is installed on this host' }
            if ($ca['ClientAccessEcpFolder'] -eq $true -or $ca['FrontEndEcpFolder'] -eq $true) { $obs += 'ECP/EAC web application files are present on this host' }
            elseif ($ca['InstallPathKnown'] -eq $true) { $obs += 'No ECP/EAC web application on this host (consistent with a management-tools-only install)' }
        }
        $iis = $ev.IisLogSample
        if ($iis -is [System.Collections.IDictionary] -and $iis['Present'] -eq $true -and $iis['RequestsByEndpoint'] -is [System.Collections.IDictionary]) {
            $r = $iis['RequestsByEndpoint']
            if ([int]$r['Ecp'] -gt 0) { $obs += ('EAC/ECP web console used: {0} non-probe requests by {1} distinct account(s) in the IIS sample {2} to {3}' -f $r['Ecp'], $iis['EcpDistinctNonProbeUsers'], $iis['SampleFrom'], $iis['SampleTo']) }
            else { $obs += ('No non-probe EAC/ECP requests in the IIS sample {0} to {1}' -f $iis['SampleFrom'], $iis['SampleTo']) }
            if ([int]$r['PowerShell'] -gt 0) {
                $apps = @(); foreach ($k in @($iis['PowerShellByClientApplication'].Keys)) { $apps += ('{0}={1}' -f $k, $iis['PowerShellByClientApplication'][$k]) }
                $obs += ('Remote PowerShell (EMS / EMC / scripts) used: {0} non-probe requests by {1} distinct account(s){2}' -f $r['PowerShell'], $iis['PowerShellDistinctNonProbeUsers'], $(if ($apps.Count -gt 0) { ' (clientApplication: ' + ($apps -join ', ') + ')' } else { '' }))
            }
        }
        $ml = $ev.ManagementEventLog
        if ($ml -is [System.Collections.IDictionary] -and $ml['Present'] -eq $true) {
            $obs += ('MSExchange Management log: {0} cmdlet events in the last 30 days ({1} non-read)' -f $ml['CmdletEventsLast30Days'], $ml['NonReadCmdletEventsLast30Days'])
            if ($ml['ByClientApplication'] -is [System.Collections.IDictionary] -and $ml['ByClientApplication'].Count -gt 0) {
                $apps = @(); foreach ($k in @($ml['ByClientApplication'].Keys)) { $apps += ('{0}={1}' -f $k, $ml['ByClientApplication'][$k]) }
                $obs += ('ClientApplication tokens in the management log: ' + ($apps -join ', '))
            }
        }
        $ot = $ev.OperatorTraces
        if ($ot -is [System.Collections.IDictionary] -and $ot['OperatorMmcRecentListIncludesExchangeConsole'] -eq $true) { $obs += 'The account running this script has an Exchange MMC console in its MMC recent-file list' }
    }
    catch { }
    if ($obs.Count -eq 0) { $obs += 'No management-interface evidence could be collected on this host' }
    $ev.Observed = $obs
    $script:Ctx.ManagementInterfaceObserved = ($obs -join '; ')
    return $ev
}

# =======================================================================================
# SECTION C (part 2) - Exchange footprint via cmdlets (falls back gracefully)
# =======================================================================================
function Get-ExchangeFootprintSection {
    $out = [ordered]@{}
    $out.ToolsLoaded  = $script:Ctx.ExchangeToolsLoaded
    $out.ToolsMethod  = $script:Ctx.ExchangeToolsMethod
    $out.ToolsMode    = $script:Ctx.ExchangeToolsMode
    $out.LoadAttempts = @($script:Ctx.ExchangeToolsAttempts)
    $out.ViewEntireForestSet = $script:Ctx.ViewEntireForestSet
    $local = $env:COMPUTERNAME

    # --- Servers -------------------------------------------------------------------------
    if (Test-CmdletAvailable -Name 'Get-ExchangeServer') {
        $out.Servers = Invoke-Guarded -What 'Get-ExchangeServer' -Script {
            @(Get-ExchangeServer -ErrorAction Stop | ForEach-Object {
                $s = Select-SafeProperties -InputObject $_ -Properties @('Name', 'Fqdn', 'ServerRole', 'Edition', 'AdminDisplayVersion', 'Site', 'IsHubTransportServer', 'IsClientAccessServer', 'IsMailboxServer', 'IsEdgeServer', 'IsUnifiedMessagingServer', 'IsFrontendTransportServer', 'IsProvisionedServer', 'IsExchangeTrialEdition', 'RemainingTrialPeriod', 'ProductID', 'IsE14OrLater', 'IsE15OrLater', 'StaticDomainControllers', 'StaticGlobalCatalogs', 'StaticConfigDomainController', 'WhenCreated') -HostnameProperties @('Name', 'Fqdn', 'StaticDomainControllers', 'StaticGlobalCatalogs', 'StaticConfigDomainController')
                $s['IsLocalMachine'] = ("$($_.Name)" -ieq $local)
                $s['FriendlyVersion'] = ConvertFrom-ExchangeVersionString -Text "$($_.AdminDisplayVersion)"
                if ($s.Contains('Site')) { $s['Site'] = Protect-Hostname -Value (Get-DnFirstComponent -Dn "$($s['Site'])") }
                $s
            })
        }
        $out.ServerCount = Get-SafeCount -Value $out.Servers
    }
    else { $out.Servers = $null; $out.Note = (Get-CmdletUnavailableNote -Cmdlet 'Get-ExchangeServer') + ' See ExchangeDetection.ActiveDirectory.Servers.' }

    # --- Local install, services -------------------------------------------------------
    $out.LocalInstallPath = $script:Ctx.ExchangeInstallPath
    $out.LocalServices = Invoke-Guarded -What 'Exchange services' -Script {
        $svcs = @(Get-CimSafe -Class 'Win32_Service' -Filter "Name LIKE 'MSExchange%' OR Name='W3SVC' OR Name='IISADMIN' OR Name='SMTPSVC' OR Name='ADSync' OR Name LIKE '%Hybrid%' OR Name='WinRM' OR Name LIKE 'MSSQL%' OR Name='RemoteAccess'")
        @(foreach ($s in $svcs) {
            [ordered]@{
                Name        = $s.Name
                DisplayName = $s.DisplayName
                State       = $s.State
                StartMode   = $s.StartMode
                RunAs       = Protect-Account -Value "$($s.StartName)"
            }
        })
    }

    # --- Certificates --------------------------------------------------------------------
    $out.Certificates = Invoke-Guarded -What 'Certificates' -Script {
        $certs = @()
        if (Test-CmdletAvailable -Name 'Get-ExchangeCertificate') {
            $params = @{ ErrorAction = 'Stop' }
            if (Test-CmdletParameter -Cmdlet 'Get-ExchangeCertificate' -Parameter 'Server') { $params['Server'] = $local }
            foreach ($c in @(Get-ExchangeCertificate @params)) {
                $subjectCn = $null; if ("$($c.Subject)" -match 'CN=([^,]+)') { $subjectCn = $Matches[1] }
                $issuerCn  = $null; if ("$($c.Issuer)" -match 'CN=([^,]+)') { $issuerCn = $Matches[1] }
                $certs += [ordered]@{
                    Source           = 'Get-ExchangeCertificate'
                    ThumbprintPrefix = "$($c.Thumbprint)".Substring(0, [math]::Min(8, "$($c.Thumbprint)".Length))
                    SubjectCN        = Protect-Hostname -Value $subjectCn
                    IssuerCN         = Protect-CertificateIssuer -IssuerCN $issuerCn
                    IssuerIsPublicCA = Test-PublicCertificateAuthority -IssuerCN $issuerCn
                    IsSelfSigned     = Get-PropertySafe -InputObject $c -Name 'IsSelfSigned'
                    NotBefore        = ConvertTo-IsoString -Value $c.NotBefore
                    NotAfter         = ConvertTo-IsoString -Value $c.NotAfter
                    DaysUntilExpiry  = [int]([DateTime]$c.NotAfter - (Get-Date)).TotalDays
                    Services         = "$($c.Services)"
                    Status           = "$(Get-PropertySafe -InputObject $c -Name 'Status')"
                    HasPrivateKey    = Get-PropertySafe -InputObject $c -Name 'HasPrivateKey'
                    DomainCount      = Get-SafeCount -Value (Get-PropertySafe -InputObject $c -Name 'CertificateDomains')
                    Domains          = Protect-HostnameList -Values @(Get-PropertySafe -InputObject $c -Name 'CertificateDomains')
                }
            }
        }
        else {
            # No-tools fallback: LocalMachine\My filtered to server-authentication certificates
            # only (S/MIME, client-auth-only and code-signing certificates are skipped).
            $skipped = 0
            foreach ($c in @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop)) {
                if (-not (Test-ServerAuthenticationCertificate -Certificate $c)) { $skipped++; continue }
                $subjectCn = $null; if ("$($c.Subject)" -match 'CN=([^,]+)') { $subjectCn = $Matches[1] }
                $issuerCn  = $null; if ("$($c.Issuer)" -match 'CN=([^,]+)') { $issuerCn = $Matches[1] }
                $certs += [ordered]@{
                    Source           = 'LocalMachine\My store (server-authentication certificates only)'
                    ThumbprintPrefix = "$($c.Thumbprint)".Substring(0, [math]::Min(8, "$($c.Thumbprint)".Length))
                    SubjectCN        = Protect-Hostname -Value $subjectCn
                    IssuerCN         = Protect-CertificateIssuer -IssuerCN $issuerCn
                    IssuerIsPublicCA = Test-PublicCertificateAuthority -IssuerCN $issuerCn
                    IsSelfSigned     = ("$($c.Subject)" -eq "$($c.Issuer)")
                    NotBefore        = ConvertTo-IsoString -Value $c.NotBefore
                    NotAfter         = ConvertTo-IsoString -Value $c.NotAfter
                    DaysUntilExpiry  = [int]($c.NotAfter - (Get-Date)).TotalDays
                    HasPrivateKey    = $c.HasPrivateKey
                    DomainCount      = Get-SafeCount -Value (Get-PropertySafe -InputObject $c -Name 'DnsNameList')
                    Domains          = Protect-HostnameList -Values @(foreach ($d in @(Get-PropertySafe -InputObject $c -Name 'DnsNameList')) { "$d" })
                }
            }
            if ($skipped -gt 0) { $certs += [ordered]@{ Source = 'LocalMachine\My store'; Note = ('{0} non-server-authentication certificate(s) in the store were not enumerated.' -f $skipped) } }
        }
        ,$certs
    }

    # --- Virtual directories / client access URLs ---------------------------------------
    $out.VirtualDirectories = Invoke-Guarded -What 'Virtual directories' -Script {
        $vd = [ordered]@{}
        $map = [ordered]@{
            Owa          = 'Get-OwaVirtualDirectory'
            Ecp          = 'Get-EcpVirtualDirectory'
            WebServices  = 'Get-WebServicesVirtualDirectory'
            ActiveSync   = 'Get-ActiveSyncVirtualDirectory'
            Oab          = 'Get-OabVirtualDirectory'
            Autodiscover = 'Get-AutodiscoverVirtualDirectory'
            Mapi         = 'Get-MapiVirtualDirectory'
            PowerShell   = 'Get-PowerShellVirtualDirectory'
            OutlookAnywhere = 'Get-OutlookAnywhere'
        }
        foreach ($k in $map.Keys) {
            $cmd = $map[$k]
            if (-not (Test-CmdletAvailable -Name $cmd)) { $vd[$k] = Get-CmdletUnavailableNote -Cmdlet $cmd; continue }
            if (Test-PastDeadline) { $vd[$k] = 'skipped: deadline'; continue }
            try {
                $params = @{ ErrorAction = 'Stop' }
                if (Test-CmdletParameter -Cmdlet $cmd -Parameter 'Server') { $params['Server'] = $local }
                if (Test-CmdletParameter -Cmdlet $cmd -Parameter 'ADPropertiesOnly') { $params['ADPropertiesOnly'] = $true }
                $vd[$k] = @(& $cmd @params | ForEach-Object {
                    Select-SafeProperties -InputObject $_ -Properties @('Name', 'Server', 'InternalUrl', 'ExternalUrl', 'InternalHostname', 'ExternalHostname', 'InternalAuthenticationMethods', 'ExternalAuthenticationMethods', 'BasicAuthentication', 'WindowsAuthentication', 'FormsAuthentication', 'OAuthAuthentication', 'IISAuthenticationMethods', 'ExternalClientAuthenticationMethod', 'InternalClientAuthenticationMethod', 'SSLOffloading', 'RequireSSL', 'WSSecurityAuthentication', 'MRSProxyEnabled') -HostnameProperties @('Server', 'InternalHostname', 'ExternalHostname') -UrlProperties @('InternalUrl', 'ExternalUrl')
                })
            }
            catch { $vd[$k] = 'ERROR: ' + (ConvertTo-SafeError -ErrorRecord $_) }
        }
        $casCmd = $null
        if (Test-CmdletAvailable -Name 'Get-ClientAccessService') { $casCmd = 'Get-ClientAccessService' } elseif (Test-CmdletAvailable -Name 'Get-ClientAccessServer') { $casCmd = 'Get-ClientAccessServer' }
        if ($casCmd) {
            try {
                $vd['AutodiscoverServiceInternalUri'] = @(& $casCmd -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ Server = (Protect-Hostname -Value "$($_.Name)"); AutoDiscoverServiceInternalUri = (Protect-Url -Value "$($_.AutoDiscoverServiceInternalUri)"); AutoDiscoverSiteScope = (Protect-HostnameList -Values @(ConvertTo-SafeValue -Value $_.AutoDiscoverSiteScope)) }
                })
            }
            catch { $vd['AutodiscoverServiceInternalUri'] = 'ERROR: ' + (ConvertTo-SafeError -ErrorRecord $_) }
        }
        $vd
    }

    # --- RBAC customisation (EAC/RBAC dependency signal for the EMT option) --------------
    $out.Rbac = Invoke-Guarded -What 'RBAC' -Script {
        $r = [ordered]@{}
        $builtIn = @('Organization Management', 'Recipient Management', 'View-Only Organization Management', 'Public Folder Management',
            'UM Management', 'Help Desk', 'Records Management', 'Discovery Management', 'Server Management', 'Delegated Setup',
            'Hygiene Management', 'Compliance Management', 'Security Reader', 'Security Administrator')
        if (Test-CmdletAvailable -Name 'Get-RoleGroup') {
            $groups = @(Get-RoleGroup -ErrorAction Stop)
            $r.RoleGroups = @(foreach ($g in $groups) {
                $memberCount = $null
                if (Test-CmdletAvailable -Name 'Get-RoleGroupMember') { try { $memberCount = Get-SafeCount -Value @(Get-RoleGroupMember -Identity "$($g.Identity)" -ErrorAction Stop) } catch { } }
                $isBuiltIn = ($builtIn -contains "$($g.Name)")
                [ordered]@{ Name = $(if ($isBuiltIn) { "$($g.Name)" } else { Protect-Hostname -Value "$($g.Name)" }); IsBuiltIn = $isBuiltIn; MemberCount = $memberCount; RoleCount = (Get-SafeCount -Value (Get-PropertySafe -InputObject $g -Name 'Roles')) }
            })
            $r.CustomRoleGroupCount = @($groups | Where-Object { $builtIn -notcontains "$($_.Name)" }).Count
        }
        else { $r.Note = Get-CmdletUnavailableNote -Cmdlet 'Get-RoleGroup' }
        if (Test-CmdletAvailable -Name 'Get-ManagementRole') {
            $roles = @(Get-ManagementRole -ErrorAction Stop)
            $r.ManagementRoleCount = $roles.Count
            $r.CustomManagementRoleCount = @($roles | Where-Object { $null -ne (Get-PropertySafe -InputObject $_ -Name 'Parent') -and "$(Get-PropertySafe -InputObject $_ -Name 'IsRootRole')" -ne 'True' }).Count
        }
        if (Test-CmdletAvailable -Name 'Get-ManagementScope') { $r.CustomManagementScopes = @(Get-ManagementScope -ErrorAction Stop | ForEach-Object { Protect-Hostname -Value "$($_.Name)" }); $r.CustomManagementScopeCount = Get-SafeCount -Value $r.CustomManagementScopes }
        if (Test-CmdletAvailable -Name 'Get-RoleAssignmentPolicy') { $r.RoleAssignmentPolicyCount = @(Get-RoleAssignmentPolicy -ErrorAction Stop).Count }
        if (Test-CmdletAvailable -Name 'Get-AdminAuditLogConfig') {
            $a = Get-AdminAuditLogConfig -ErrorAction Stop
            $r.AdminAuditLog = Select-SafeProperties -InputObject $a -Properties @('AdminAuditLogEnabled', 'AdminAuditLogAgeLimit', 'UnifiedAuditLogIngestionEnabled')
        }
        $r
    }

    # --- Databases -----------------------------------------------------------------------
    # Count, hosting server, replication type, mounted state and size are the design inputs.
    # Backup timestamps, EDB/log paths and circular logging are not collected.
    if (Test-CmdletAvailable -Name 'Get-MailboxDatabase') {
        $out.MailboxDatabases = Invoke-Guarded -What 'Get-MailboxDatabase' -Script {
            # Enumerated WITHOUT -Status (finding 26): -Status makes an RPC call to every hosting
            # server and blocks for the full RPC timeout on each offline DAG member. Mounted state
            # and size are then fetched per database only when the hosting server answers on
            # TCP 135 within 2 s (the local server always qualifies).
            $dbs = @(Get-MailboxDatabase -ErrorAction Stop)
            $hasStatus = Test-CmdletParameter -Cmdlet 'Get-MailboxDatabase' -Parameter 'Status'
            $reachable = @{}
            @(foreach ($db in $dbs) {
                $d = Select-SafeProperties -InputObject $db -Properties @('Name', 'Server', 'ServerName', 'ReplicationType', 'MasterServerOrAvailabilityGroup', 'Recovery', 'IsExcludedFromProvisioning') -HostnameProperties @('Name', 'Server', 'ServerName', 'MasterServerOrAvailabilityGroup')
                $srv = "$(Get-PropertySafe -InputObject $db -Name 'ServerName')"
                if (-not $srv) { $srv = "$(Get-PropertySafe -InputObject $db -Name 'Server')" }
                $srvKey = $srv.ToLowerInvariant()
                if (-not $reachable.ContainsKey($srvKey)) {
                    if (-not $srv) { $reachable[$srvKey] = $false }
                    elseif ($srv -ieq $local -or $srv -like "$local.*") { $reachable[$srvKey] = $true }
                    elseif ($script:SkipNet) { $reachable[$srvKey] = $false }
                    else { $reachable[$srvKey] = ((Test-TcpPort -TargetHost $srv -Port 135 -TimeoutMs 2000).Result -eq 'Open') }
                }
                $d['HostingServerReachable'] = $reachable[$srvKey]
                $d['StatusQueried'] = $false
                if ($hasStatus -and $reachable[$srvKey] -and -not (Test-PastDeadline)) {
                    try {
                        $st = Get-MailboxDatabase -Identity "$($db.Identity)" -Status -ErrorAction Stop
                        $d['Mounted']        = Get-PropertySafe -InputObject $st -Name 'Mounted'
                        $d['DatabaseSize']   = "$(Get-PropertySafe -InputObject $st -Name 'DatabaseSize')"
                        $d['DatabaseSizeGB'] = ConvertTo-GigabytesFromSizeText -Text $d['DatabaseSize']
                        $d['StatusQueried']  = $true
                    }
                    catch { $d['StatusError'] = ConvertTo-SafeError -ErrorRecord $_ }
                }
                elseif (-not $reachable[$srvKey]) { $d['StatusNote'] = 'Hosting server did not answer on TCP 135 (or network tests are disabled); mounted state and size not queried.' }
                $d
            })
        }
        $out.MailboxDatabaseCount = Get-SafeCount -Value $out.MailboxDatabases
        $out.MailboxDatabaseTotalSizeGB = Invoke-Guarded -What 'Database size total' -Script {
            $t = [double]0; $n = 0
            foreach ($d in @($out.MailboxDatabases)) { if ($d -is [System.Collections.IDictionary] -and $null -ne $d['DatabaseSizeGB']) { $t += [double]$d['DatabaseSizeGB']; $n++ } }
            if ($n -eq 0) { $null } else { [math]::Round($t, 1) }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-PublicFolderDatabase') {
        $out.PublicFolderDatabases = Invoke-Guarded -What 'Get-PublicFolderDatabase' -Script {
            @(Get-PublicFolderDatabase -ErrorAction Stop | ForEach-Object { Select-SafeProperties -InputObject $_ -Properties @('Name', 'Server') -HostnameProperties @('Name', 'Server') })
        }
        $out.PublicFolderDatabaseCount = Get-SafeCount -Value $out.PublicFolderDatabases
    }
    if (Test-CmdletAvailable -Name 'Get-DatabaseAvailabilityGroup') {
        $out.DatabaseAvailabilityGroups = Invoke-Guarded -What 'Get-DatabaseAvailabilityGroup' -Script {
            @(Get-DatabaseAvailabilityGroup -ErrorAction Stop | ForEach-Object { [ordered]@{ Name = (Protect-Hostname -Value "$($_.Name)"); ServerCount = (Get-SafeCount -Value (Get-PropertySafe -InputObject $_ -Name 'Servers')); WitnessServer = (Protect-Hostname -Value "$($_.WitnessServer)") } })
        }
    }

    # --- How is this server administered? Measured evidence (finding 33) -----------------
    $out.ManagementInterfaceEvidence = Get-ManagementInterfaceEvidence

    return $out
}

# =======================================================================================
# SECTION D - Is the server doing anything besides recipient management?
# =======================================================================================
$script:DefaultConnectorNamePattern = '^(?<pfx>Default Frontend|Client Frontend|Client Proxy|Outbound Proxy Frontend|Default|Client)\s+(?<srv>\S+)$'

function Test-DefaultConnectorName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return [bool]($Name -match $script:DefaultConnectorNamePattern -or $Name -eq 'Intra-Organization SMTP Send Connector' -or $Name -match '^Intra-Organization SMTP Send')
}

function Protect-ConnectorName {
    # Default connector names embed the server name ('Default Frontend EX01'); keep the prefix
    # and route the server token through Protect-Hostname. Custom names are organisation data
    # and go through Protect-Hostname whole (clear by default, hashed under -RedactHostnames).
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Name -match $script:DefaultConnectorNamePattern) { return ($Matches['pfx'] + ' ' + (Protect-Hostname -Value $Matches['srv'])) }
    if ($Name -match '^Intra-Organization SMTP Send') { return $Name }
    return (Protect-Hostname -Value $Name)
}

function Protect-ConnectorId {
    # 'SERVER\Connector name' -> protected server + protected connector name.
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if ($Id -match '^(?<srv>[^\\]+)\\(?<name>.+)$') { return ((Protect-Hostname -Value $Matches['srv']) + '\' + (Protect-ConnectorName -Name $Matches['name'])) }
    return (Protect-ConnectorName -Name $Id)
}

function Get-NonRecipientWorkloadSection {
    $out = [ordered]@{}
    $local = $env:COMPUTERNAME

    # --- Receive connectors (org-wide, flagging the local server) ------------------------
    if (Test-CmdletAvailable -Name 'Get-ReceiveConnector') {
        $out.ReceiveConnectors = Invoke-Guarded -What 'Get-ReceiveConnector' -Script {
            $canReadPerms = Test-CmdletAvailable -Name 'Get-ADPermission'
            @(Get-ReceiveConnector -ErrorAction Stop | ForEach-Object {
                $rc = $_
                $permGroups = "$($rc.PermissionGroups)"
                $anonymousPermGroup = ($permGroups -match 'Anonymous')
                $acceptAnyRecipient = $null
                if ($canReadPerms -and -not (Test-PastDeadline)) {
                    try {
                        $perms = @(Get-ADPermission -Identity "$($rc.Identity)" -ErrorAction Stop | Where-Object {
                            "$($_.User)" -match 'ANONYMOUS' -and "$($_.ExtendedRights)" -match 'ms-Exch-SMTP-Accept-Any-Recipient' -and -not $_.Deny })
                        $acceptAnyRecipient = ($perms.Count -gt 0)
                    }
                    catch { $acceptAnyRecipient = 'unreadable' }
                }
                $serverName = "$(Get-PropertySafe -InputObject $rc -Name 'Server')"
                $name = "$($rc.Name)"
                $isDefaultName = Test-DefaultConnectorName -Name $name
                $r = [ordered]@{
                    Name                   = Protect-ConnectorName -Name $name
                    Server                 = Protect-Hostname -Value $serverName
                    IsLocalServer          = ($serverName -ieq $local)
                    Enabled                = Get-PropertySafe -InputObject $rc -Name 'Enabled'
                    TransportRole          = "$(Get-PropertySafe -InputObject $rc -Name 'TransportRole')"
                    Bindings               = @(ConvertTo-SafeValue -Value $rc.Bindings)
                    RemoteIPRangeCount     = Get-SafeCount -Value (Get-PropertySafe -InputObject $rc -Name 'RemoteIPRanges')
                    RemoteIPRanges         = @(ConvertTo-SafeValue -Value $rc.RemoteIPRanges | Select-Object -First 100)
                    PermissionGroups       = $permGroups
                    AuthMechanism          = "$($rc.AuthMechanism)"
                    AnonymousUsersPermissionGroup = $anonymousPermGroup
                    AnonymousAcceptAnyRecipient   = $acceptAnyRecipient
                    RequireTLS             = Get-PropertySafe -InputObject $rc -Name 'RequireTLS'
                    Fqdn                   = Protect-Hostname -Value "$(Get-PropertySafe -InputObject $rc -Name 'Fqdn')"
                    MaxMessageSize         = "$(Get-PropertySafe -InputObject $rc -Name 'MaxMessageSize')"
                    IsDefaultConnectorName = $isDefaultName
                    # A relay connector is either custom-named or grants anonymous Accept-Any-Recipient.
                    # 'Anonymous users' on a DEFAULT frontend connector is the stock internet-inbound
                    # configuration on 2013+, not relay.
                    LooksLikeRelayConnector = ((-not $isDefaultName) -or ($acceptAnyRecipient -eq $true))
                }
                $r
            })
        }
        $out.ReceiveConnectorCount = Get-SafeCount -Value $out.ReceiveConnectors
    }
    else { $out.ReceiveConnectors = Get-CmdletUnavailableNote -Cmdlet 'Get-ReceiveConnector' }

    # --- Send connectors -----------------------------------------------------------------
    if (Test-CmdletAvailable -Name 'Get-SendConnector') {
        $out.SendConnectors = Invoke-Guarded -What 'Get-SendConnector' -Script {
            @(Get-SendConnector -ErrorAction Stop | ForEach-Object {
                $s = Select-SafeProperties -InputObject $_ -Properties @('Name', 'Enabled', 'AddressSpaces', 'SmartHosts', 'DNSRoutingEnabled', 'SourceTransportServers', 'CloudServicesMailEnabled', 'TlsDomain', 'TlsAuthLevel', 'RequireTLS', 'Fqdn', 'MaxMessageSize', 'SmartHostAuthMechanism', 'IsScopedConnector', 'Port') -HostnameProperties @('Name', 'SmartHosts', 'SourceTransportServers', 'TlsDomain', 'Fqdn')
                $s['AddressSpaces'] = Protect-HostnameList -Values @($s['AddressSpaces'])
                $s['SourcedFromLocalServer'] = [bool](@($_.SourceTransportServers | Where-Object { "$_" -ieq $local }).Count -gt 0)
                $s
            })
        }
        $out.SendConnectorCount = Get-SafeCount -Value $out.SendConnectors
    }
    else { $out.SendConnectors = Get-CmdletUnavailableNote -Cmdlet 'Get-SendConnector' }

    # --- Transport service settings / message tracking summary --------------------------
    $tsCmd = $null
    if (Test-CmdletAvailable -Name 'Get-TransportService') { $tsCmd = 'Get-TransportService' } elseif (Test-CmdletAvailable -Name 'Get-TransportServer') { $tsCmd = 'Get-TransportServer' }
    if ($tsCmd) {
        $out.TransportService = Invoke-Guarded -What $tsCmd -Script {
            $ts = & $tsCmd -Identity $local -ErrorAction Stop
            Select-SafeProperties -InputObject $ts -Properties @('Name', 'MessageTrackingLogEnabled', 'MessageTrackingLogPath', 'MessageTrackingLogMaxAge', 'MessageTrackingLogMaxDirectorySize', 'ExternalDNSServers', 'InternalDNSServers', 'ExternalIPAddress', 'MaxOutboundConnections', 'ConnectivityLogEnabled', 'ReceiveProtocolLogPath', 'SendProtocolLogPath') -HostnameProperties @('Name') -PathProperties @('MessageTrackingLogPath', 'ReceiveProtocolLogPath', 'SendProtocolLogPath')
        }
    }
    # 2013+ splits transport into Front End, Hub (Transport) and Mailbox Transport services;
    # the front end is where external SMTP arrives, so its settings are relay evidence too.
    if (Test-CmdletAvailable -Name 'Get-FrontendTransportService') {
        $out.FrontendTransportService = Invoke-Guarded -What 'Get-FrontendTransportService' -Script {
            $fe = Get-FrontendTransportService -Identity $local -ErrorAction Stop
            Select-SafeProperties -InputObject $fe -Properties @('Name', 'ReceiveProtocolLogPath', 'SendProtocolLogPath', 'ReceiveProtocolLogMaxAge', 'ExternalDNSServers', 'InternalDNSServers', 'ExternalIPAddress', 'ConnectivityLogEnabled', 'AgentLogEnabled') -HostnameProperties @('Name') -PathProperties @('ReceiveProtocolLogPath', 'SendProtocolLogPath')
        }
    }

    $out.MessageTracking = Invoke-Guarded -What 'Get-MessageTrackingLog' -Script {
        if (-not (Test-CmdletAvailable -Name 'Get-MessageTrackingLog')) { return ([ordered]@{ Available = $false; Reason = (Get-CmdletUnavailableNote -Cmdlet 'Get-MessageTrackingLog') + ' (also absent when this host has no transport role)' }) }
        $days = $script:TrackingDays
        $start = (Get-Date).Date.AddDays(-$days)
        $end   = (Get-Date)
        $cap   = 250000
        $byDay = [ordered]@{}
        $byEvent = @{}
        $bySource = @{}
        $byPair = @{}          # 'Source|EventId' (finding 36: the pair, never two independent tallies)
        $byConnector = @{}
        $byConnSmtpReceive = @{}
        $total = 0
        $truncated = $false
        $stoppedAtDeadline = $false
        $params = @{ Start = $start; End = $end; ResultSize = $cap; ErrorAction = 'Stop' }
        if (Test-CmdletParameter -Cmdlet 'Get-MessageTrackingLog' -Parameter 'Server') { $params['Server'] = $local }
        # Only Timestamp/EventId/Source/ConnectorId are ever read; sender, recipients and
        # subject are never selected and never leave the pipeline.
        try {
            Get-MessageTrackingLog @params | Select-Object -Property Timestamp, EventId, Source, ConnectorId | ForEach-Object {
                $total++
                if (($total % 5000) -eq 0) { Assert-Deadline }
                $day = $_.Timestamp.ToString('yyyy-MM-dd')
                if (-not $byDay.Contains($day)) { $byDay[$day] = 0 }
                $byDay[$day] = $byDay[$day] + 1
                $ev = "$($_.EventId)"; if (-not $byEvent.ContainsKey($ev)) { $byEvent[$ev] = 0 }; $byEvent[$ev] = $byEvent[$ev] + 1
                $src = "$($_.Source)"; if (-not $bySource.ContainsKey($src)) { $bySource[$src] = 0 }; $bySource[$src] = $bySource[$src] + 1
                $pair = $src + '|' + $ev; if (-not $byPair.ContainsKey($pair)) { $byPair[$pair] = 0 }; $byPair[$pair] = $byPair[$pair] + 1
                $conn = "$($_.ConnectorId)"
                if ($conn) {
                    if (-not $byConnector.ContainsKey($conn)) { $byConnector[$conn] = 0 }; $byConnector[$conn] = $byConnector[$conn] + 1
                    if ($ev -eq 'RECEIVE' -and $src -eq 'SMTP') { if (-not $byConnSmtpReceive.ContainsKey($conn)) { $byConnSmtpReceive[$conn] = 0 }; $byConnSmtpReceive[$conn] = $byConnSmtpReceive[$conn] + 1 }
                }
            }
        }
        catch { if (Test-DeadlineException -ErrorRecord $_) { $stoppedAtDeadline = $true } else { throw } }
        if ($total -ge $cap) { $truncated = $true }
        $byConnClean = [ordered]@{}
        foreach ($k in ($byConnector.Keys | Sort-Object)) { $byConnClean[(Protect-ConnectorId -Id $k)] = $byConnector[$k] }
        # SMTP RECEIVE events are counted per connector; default/proxy/intra-org connectors carry
        # ordinary internet and internal mail and are excluded from the relay figure.
        $smtpReceiveTotal = 0; if ($byPair.ContainsKey('SMTP|RECEIVE')) { $smtpReceiveTotal = $byPair['SMTP|RECEIVE'] }
        $smtpReceiveNonDefault = 0; $smtpReceiveDefault = 0
        $byConnRecvClean = [ordered]@{}
        foreach ($k in ($byConnSmtpReceive.Keys | Sort-Object)) {
            $nm = $k; if ($k -match '^[^\\]+\\(?<name>.+)$') { $nm = $Matches['name'] }
            if (Test-DefaultConnectorName -Name $nm) { $smtpReceiveDefault += $byConnSmtpReceive[$k] } else { $smtpReceiveNonDefault += $byConnSmtpReceive[$k] }
            $byConnRecvClean[(Protect-ConnectorId -Id $k)] = $byConnSmtpReceive[$k]
        }
        $byEventSorted = [ordered]@{}; foreach ($k in ($byEvent.Keys | Sort-Object)) { $byEventSorted[$k] = $byEvent[$k] }
        $bySourceSorted = [ordered]@{}; foreach ($k in ($bySource.Keys | Sort-Object)) { $bySourceSorted[$k] = $bySource[$k] }
        $byPairSorted = [ordered]@{}; foreach ($k in ($byPair.Keys | Sort-Object)) { $byPairSorted[$k] = $byPair[$k] }
        [ordered]@{
            Available        = $true
            WindowDays       = $days
            WindowStart      = ConvertTo-IsoString -Value $start
            WindowEnd        = ConvertTo-IsoString -Value $end
            TotalEvents      = $total
            TruncatedAtCap   = $truncated
            StoppedAtDeadline = $stoppedAtDeadline
            Cap              = $cap
            ByDay            = $byDay
            ByEventId        = $byEventSorted
            BySource         = $bySourceSorted
            BySourceAndEvent = $byPairSorted
            ByConnector      = $byConnClean
            SmtpReceiveByConnector = $byConnRecvClean
            SmtpReceiveEventsTotal = $smtpReceiveTotal
            SmtpReceiveEventsOnDefaultConnectors = $smtpReceiveDefault
            SmtpReceiveEventsOnNonDefaultConnectors = $smtpReceiveNonDefault
            ReceiveEvents    = $smtpReceiveNonDefault
            Note             = 'Aggregate counts only. No sender, recipient or subject data was read. On 2013+ transport is split across Front End, Hub and Mailbox Transport services, so row counts are not comparable with 2010.'
        }
    }

    # --- Queues (live mail flow through this box) ---------------------------------------
    if (Test-CmdletAvailable -Name 'Get-Queue') {
        $out.Queues = Invoke-Guarded -What 'Get-Queue' -Script {
            $params = @{ ErrorAction = 'Stop' }
            if (Test-CmdletParameter -Cmdlet 'Get-Queue' -Parameter 'Server') { $params['Server'] = $local }
            @(Get-Queue @params | ForEach-Object {
                [ordered]@{ DeliveryType = "$($_.DeliveryType)"; Status = "$($_.Status)"; MessageCount = $_.MessageCount; NextHopDomain = (Protect-Hostname -Value "$($_.NextHopDomain)") }
            })
        }
    }

    # --- Transport agents / rules / journaling / domains --------------------------------
    if (Test-CmdletAvailable -Name 'Get-TransportAgent') {
        $out.TransportAgents = Invoke-Guarded -What 'Get-TransportAgent' -Script {
            @(Get-TransportAgent -ErrorAction Stop | ForEach-Object {
                $rawPath = "$(Get-PropertySafe -InputObject $_ -Name 'AssemblyPath')"
                $factory = "$(Get-PropertySafe -InputObject $_ -Name 'TransportAgentFactory')"
                # Classified on the RAW path/factory before redaction; the emitted path is protected.
                $isMs = ($factory -like 'Microsoft.Exchange.*' -or $rawPath -match '(?i)\\Exchange Server\\V1[45]\\TransportRoles\\|\\Exchange Server\\V1[45]\\Bin\\|\\Microsoft\\Exchange Server\\')
                $t = Select-SafeProperties -InputObject $_ -Properties @('Identity', 'Enabled', 'Priority', 'TransportAgentFactory', 'AssemblyPath') -PathProperties @('AssemblyPath')
                $t['IsMicrosoftAgent'] = $isMs
                $t
            })
        }
        $out.TransportAgentCount = Get-SafeCount -Value $out.TransportAgents
        $out.NonMicrosoftTransportAgentCount = @($out.TransportAgents | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['IsMicrosoftAgent'] -eq $false }).Count
    }
    if (Test-CmdletAvailable -Name 'Get-TransportRule') {
        $out.TransportRules = Invoke-Guarded -What 'Get-TransportRule' -Script {
            $rules = @(Get-TransportRule -ErrorAction Stop)
            # Count and enabled count only; rule names are free text written by the client.
            [ordered]@{ Count = $rules.Count; EnabledCount = @($rules | Where-Object { "$($_.State)" -eq 'Enabled' }).Count }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-JournalRule') {
        $out.JournalRuleCount = Invoke-Guarded -What 'Get-JournalRule' -Script { @(Get-JournalRule -ErrorAction Stop).Count }
    }
    if (Test-CmdletAvailable -Name 'Get-AcceptedDomain') {
        $out.AcceptedDomains = Invoke-Guarded -What 'Get-AcceptedDomain' -Script {
            @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object {
                $d = Select-SafeProperties -InputObject $_ -Properties @('Name', 'DomainName', 'DomainType', 'Default', 'AuthenticationType', 'LiveIdInstanceType', 'AddressBookEnabled') -HostnameProperties @('Name', 'DomainName')
                $d['IsCoexistenceDomain'] = ("$($_.DomainName)" -like '*.mail.onmicrosoft.com')
                $d['IsOnMicrosoftDomain'] = ("$($_.DomainName)" -like '*.onmicrosoft.com')
                $d
            })
        }
    }
    if (Test-CmdletAvailable -Name 'Get-RemoteDomain') {
        $out.RemoteDomains = Invoke-Guarded -What 'Get-RemoteDomain' -Script {
            @(Get-RemoteDomain -ErrorAction Stop | ForEach-Object {
                $d = Select-SafeProperties -InputObject $_ -Properties @('Name', 'DomainName', 'TargetDeliveryDomain', 'IsInternal', 'TrustedMailOutboundEnabled', 'TrustedMailInboundEnabled', 'AutoForwardEnabled') -HostnameProperties @('Name', 'DomainName')
                $d
            })
        }
    }
    if (Test-CmdletAvailable -Name 'Get-EdgeSubscription') {
        $out.EdgeSubscriptionCount = Invoke-Guarded -What 'Get-EdgeSubscription' -Script { @(Get-EdgeSubscription -ErrorAction Stop).Count }
    }

    # --- Listening SMTP / relay services outside Exchange ---------------------------------
    $out.OtherSmtpServices = Invoke-Guarded -What 'Other SMTP services' -Script {
        ,@(Get-CimSafe -Class 'Win32_Service' -Filter "Name='SMTPSVC' OR DisplayName LIKE '%SMTP%' OR DisplayName LIKE '%hMailServer%' OR DisplayName LIKE '%MailEnable%' OR DisplayName LIKE '%Postfix%' OR DisplayName LIKE '%Mail Relay%'" | ForEach-Object {
            [ordered]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode }
        })
    }
    $out.OtherSmtpServiceCount = Get-SafeCount -Value $out.OtherSmtpServices

    # --- Installed programs that touch mail flow or the Exchange/Entra footprint ---------
    # Narrow on purpose: this is not a software inventory. Transport agents, non-Exchange SMTP
    # services and automation runners answer the design questions; this list only adds
    # mail-adjacent products (mail security, signatures, archiving, fax, sync/hybrid components).
    $out.MailRelatedPrograms = Invoke-Guarded -What 'Mail-related programs' -Script {
        $progs = Get-InstalledProgramList
        $pattern = '(?i)Exchange|SMTP|Mimecast|Proofpoint|Barracuda|ScanMail|Symantec (Mail|Messaging)|Trend Micro (ScanMail|IMSS|Email)|ESET Mail|Sophos.*(Exchange|Email)|McAfee.*(Exchange|GroupShield|Email)|Kaspersky.*(Exchange|Mail)|Forcepoint Email|SpamTitan|MailEnable|hMailServer|Postfix|Papercut|GFI Mail|GFI Archiver|Kemp|CodeTwo|Exclaimer|Signature Manager|Hybrid (Configuration|Service|Agent)|Azure AD Connect|Entra Connect|Azure Active Directory Connect|Microsoft Online Services Sign-in|BitTitan|Binary Tree|Quest.*(Migration|Exchange|Archive)|Veeam.*(Exchange|Backup)|Backup Exec|MailStore|Enterprise Vault|Archiv|Journal|Fax|Mail Relay|SMTP Relay'
        ,@($progs | Where-Object { "$($_.DisplayName)" -match $pattern } | Sort-Object DisplayName | Select-Object -First 40 | ForEach-Object {
            [ordered]@{ DisplayName = $_.DisplayName; Version = $_.DisplayVersion; Publisher = $_.Publisher }
        })
    }

    # --- IIS sites and applications (anything that is not Exchange?) --------------------
    $out.Iis = Invoke-Guarded -What 'IIS' -Script {
        $iis = [ordered]@{}
        $loaded = $false
        try { Import-Module WebAdministration -ErrorAction Stop -WarningAction SilentlyContinue; $loaded = $true } catch { }
        if (-not $loaded) { try { if (Get-PSSnapin -Registered -Name WebAdministration -ErrorAction SilentlyContinue) { Add-PSSnapin WebAdministration -ErrorAction Stop; $loaded = $true } } catch { } }
        $exchangeApps = @('owa', 'ecp', 'ews', 'mapi', 'oab', 'powershell', 'rpc', 'rpcwithcert', 'autodiscover', 'microsoft-server-activesync', 'aspnet_client', 'exchange', 'exchweb', 'public', 'pushnotifications', 'exadmin', 'microsoft-server-activesync/proxy')
        $exchangeSites = @('Default Web Site', 'Exchange Back End')
        $stockPools = @('DefaultAppPool', 'Classic .NET AppPool', '.NET v4.5', '.NET v4.5 Classic', '.NET v2.0', '.NET v2.0 Classic')
        if ($loaded -and (Test-CmdletAvailable -Name 'Get-Website')) {
            $iis.Sites = @(Get-Website -ErrorAction Stop | ForEach-Object {
                $bindings = @()
                try { foreach ($b in $_.bindings.Collection) { $bindings += ("{0} {1}" -f $b.protocol, $b.bindingInformation) } } catch { }
                $isEx = ($exchangeSites -contains "$($_.Name)")
                [ordered]@{ Name = $(if ($isEx) { "$($_.Name)" } else { Protect-Hostname -Value "$($_.Name)" }); State = "$($_.State)"; PhysicalPath = (Protect-FilePath -Value "$($_.PhysicalPath)"); Bindings = (Protect-HostnameList -Values $bindings); IsExchangeSite = $isEx }
            })
            $apps = @()
            if (Test-CmdletAvailable -Name 'Get-WebApplication') {
                foreach ($a in @(Get-WebApplication -ErrorAction Stop)) {
                    $appPath = "$($a.path)".TrimStart('/').ToLowerInvariant()
                    $siteName = $null
                    try { $siteName = "$($a.GetParentElement().Attributes['name'].Value)" } catch { $siteName = $null }
                    $isExApp = ($exchangeApps -contains $appPath)
                    $pool = "$($a.applicationPool)"
                    $apps += [ordered]@{
                        Site            = $(if ($exchangeSites -contains $siteName) { $siteName } else { Protect-Hostname -Value $siteName })
                        Path            = $(if ($isExApp) { "$($a.path)" } else { Protect-Hostname -Value "$($a.path)" })
                        ApplicationPool = $(if ($pool -like 'MSExchange*' -or $stockPools -contains $pool) { $pool } else { Protect-Hostname -Value $pool })
                        PhysicalPath    = Protect-FilePath -Value "$($a.PhysicalPath)"
                        IsExchangeApp   = $isExApp
                    }
                }
            }
            $iis.Applications = $apps
            $iis.NonExchangeApplicationCount = @($apps | Where-Object { -not $_['IsExchangeApp'] }).Count
            $iis.NonExchangeSiteCount = @($iis.Sites | Where-Object { -not $_['IsExchangeSite'] }).Count
        }
        else {
            $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
            if (Test-Path -LiteralPath $appcmd) {
                # WebAdministration unavailable: site and app COUNTS only from appcmd (the raw
                # listing carries names and paths and is not emitted).
                $iis.Note = 'WebAdministration module unavailable; counts taken from appcmd.'
                $siteLines = @(& $appcmd list site 2>$null)
                $appLines  = @(& $appcmd list app 2>$null)
                $iis.SiteCount = $siteLines.Count
                $iis.ApplicationCount = $appLines.Count
                $iis.NonExchangeSiteCount = @($siteLines | Where-Object { $_ -notmatch '^SITE "(Default Web Site|Exchange Back End)"' }).Count
                $iis.NonExchangeApplicationCount = @($appLines | Where-Object { $_ -notmatch ('^APP "(Default Web Site|Exchange Back End)/(' + (($exchangeApps | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')?"') }).Count
            }
            else { $iis.Note = 'IIS not installed or not readable.' }
        }
        $iis
    }

    # --- Installed Windows roles / notable features -------------------------------------
    $out.WindowsRoles = Invoke-Guarded -What 'Windows roles' -Script {
        if (-not (Test-CmdletAvailable -Name 'Get-WindowsFeature')) { try { Import-Module ServerManager -ErrorAction Stop -WarningAction SilentlyContinue } catch { } }
        if (-not (Test-CmdletAvailable -Name 'Get-WindowsFeature')) { return 'Get-WindowsFeature not available (client OS or module missing)' }
        $feat = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed })
        $roles = @($feat | Where-Object { "$($_.FeatureType)" -eq 'Role' } | ForEach-Object { $_.Name })
        $notable = @($feat | Where-Object { $_.Name -in @('RemoteAccess', 'DirectAccess-VPN', 'Routing', 'ADFS-Federation', 'DHCP', 'DNS', 'FS-FileServer', 'Print-Server', 'Web-Server', 'RSAT-AD-PowerShell', 'RSAT-ADDS', 'AD-Domain-Services', 'Web-WHC', 'NPAS', 'Fax', 'Hyper-V', 'Containers', 'WDS', 'Web-Ftp-Server', 'SMTP-Server', 'Windows-Server-Backup') } | ForEach-Object { $_.Name })
        [ordered]@{ InstalledRoleNames = $roles; NotableFeatures = $notable; InstalledFeatureCount = $feat.Count }
    }

    return $out
}

$script:InstalledProgramCache = $null
function Get-InstalledProgramList {
    # Reads the Uninstall registry keys (64-bit, 32-bit and per-user) once per run. Read-only.
    if ($null -ne $script:InstalledProgramCache) { return ,$script:InstalledProgramCache }
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $list = @()
    foreach ($p in $paths) {
        try {
            $list += @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation)
        }
        catch { }
    }
    $script:InstalledProgramCache = $list
    return ,$list
}

# =======================================================================================
# SECTION E - Recipient inventory: COUNTS ONLY, never names
# =======================================================================================
$script:RecipientTypeDetailsMap = @{
    1 = 'UserMailbox'; 2 = 'LinkedMailbox'; 4 = 'SharedMailbox'; 8 = 'LegacyMailbox'; 16 = 'RoomMailbox'; 32 = 'EquipmentMailbox';
    64 = 'MailContact'; 128 = 'MailUser'; 256 = 'MailUniversalDistributionGroup'; 512 = 'MailNonUniversalGroup';
    1024 = 'MailUniversalSecurityGroup'; 2048 = 'DynamicDistributionGroup'; 4096 = 'PublicFolder'; 8192 = 'SystemAttendantMailbox';
    16384 = 'SystemMailbox'; 32768 = 'CrossForestMailContact'; 65536 = 'User'; 131072 = 'Contact'; 262144 = 'UniversalDistributionGroup';
    524288 = 'UniversalSecurityGroup'; 1048576 = 'NonUniversalGroup'; 2097152 = 'DisabledUser'; 4194304 = 'MicrosoftExchange';
    8388608 = 'ArbitrationMailbox'; 16777216 = 'MailboxPlan'; 33554432 = 'LinkedUser'; 268435456 = 'RoomList';
    536870912 = 'DiscoveryMailbox'; 1073741824 = 'RoleGroup'; 2147483648 = 'RemoteUserMailbox'; 4294967296 = 'Computer';
    8589934592 = 'RemoteRoomMailbox'; 17179869184 = 'RemoteEquipmentMailbox'; 34359738368 = 'RemoteSharedMailbox';
    68719476736 = 'PublicFolderMailbox'; 137438953472 = 'TeamMailbox'; 274877906944 = 'RemoteTeamMailbox';
    549755813888 = 'MonitoringMailbox'; 1099511627776 = 'GroupMailbox'; 2199023255552 = 'LinkedRoomMailbox';
    4398046511104 = 'AuditLogMailbox'; 8796093022208 = 'RemoteGroupMailbox'; 17592186044416 = 'SchedulingMailbox';
    35184372088832 = 'GuestMailUser'; 70368744177664 = 'AuxAuditLogMailbox'; 140737488355328 = 'SupervisoryReviewPolicyMailbox';
    281474976710656 = 'ExchangeSecurityGroup'; 562949953421312 = 'SubstrateGroup'
}
# Re-key by string so that [int] and [long] values look up consistently.
$script:RecipientTypeDetailsByString = @{}
foreach ($rtdKey in @($script:RecipientTypeDetailsMap.Keys)) { $script:RecipientTypeDetailsByString["$rtdKey"] = $script:RecipientTypeDetailsMap[$rtdKey] }

function Get-RecipientCountFromAd {
    # Counts msExchRecipientTypeDetails across every domain in the forest via LDAP. Rows are
    # streamed (never materialised) and only the numeric type attribute is requested; no names
    # or addresses are read. Bounded by the global deadline and a 250,000-row cap per domain.
    $counts = @{}
    $domainsQueried = 0
    $errors = @()
    $rowsSeen = 0
    $truncated = $false
    $stoppedAtDeadline = $false
    $domainNcs = @($script:Ctx.DomainNcs)
    if ($domainNcs.Count -eq 0 -and $script:Ctx.DefaultNC) { $domainNcs = @($script:Ctx.DefaultNC) }
    $cap = 250000
    foreach ($nc in $domainNcs) {
        if (Test-PastDeadline) { $stoppedAtDeadline = $true; break }
        try {
            $n = Search-Directory -SearchBase ("LDAP://" + $nc) -Filter '(msExchRecipientTypeDetails=*)' -Properties @('msExchRecipientTypeDetails') -Scope 'Subtree' -SizeLimit $cap -TimeoutSeconds 300 -RowAction {
                param($r)
                $v = 0
                try { $v = [long](Get-AdsiPropertyString -SearchResult $r -Name 'msExchRecipientTypeDetails') } catch { return }
                $name = $(if ($script:RecipientTypeDetailsByString.ContainsKey("$v")) { $script:RecipientTypeDetailsByString["$v"] } else { "Unknown($v)" })
                if (-not $counts.ContainsKey($name)) { $counts[$name] = 0 }
                $counts[$name] = $counts[$name] + 1
            }
            $rowsSeen += [int]$n
            if ([int]$n -ge $cap) { $truncated = $true }
            $domainsQueried++
        }
        catch {
            if (Test-DeadlineException -ErrorRecord $_) { $stoppedAtDeadline = $true; break }
            $errors += ('{0}: {1}' -f (Protect-Hostname -Value (ConvertTo-DomainFqdn -Dn $nc)), (ConvertTo-SafeError -ErrorRecord $_))
        }
    }
    $ordered = [ordered]@{}
    foreach ($k in ($counts.Keys | Sort-Object)) { $ordered[$k] = $counts[$k] }
    return ([ordered]@{ DomainsQueried = $domainsQueried; DomainsInForest = $domainNcs.Count; RowsCounted = $rowsSeen; TruncatedAtCap = $truncated; StoppedAtDeadline = $stoppedAtDeadline; Counts = $ordered; Errors = $errors })
}

function Get-GroupedCountFromCmdlet {
    # Enumerates a recipient cmdlet and groups by RecipientTypeDetails, reading only that
    # property. Returns @{ Total; <type>=count...; StoppedAtDeadline }.
    param([string]$Cmdlet, [hashtable]$ExtraParams = @{})
    $groups = @{}
    $total = 0
    $stopped = $false
    $p = @{ ResultSize = 'Unlimited'; ErrorAction = 'Stop' }
    foreach ($k in $ExtraParams.Keys) { $p[$k] = $ExtraParams[$k] }
    try {
        & $Cmdlet @p | Select-Object -Property RecipientTypeDetails | ForEach-Object {
            $total++
            if (($total % 2000) -eq 0) { Assert-Deadline }
            $t = "$($_.RecipientTypeDetails)"; if (-not $groups.ContainsKey($t)) { $groups[$t] = 0 }; $groups[$t] = $groups[$t] + 1
        }
    }
    catch { if (Test-DeadlineException -ErrorRecord $_) { $stopped = $true } else { throw } }
    $o = [ordered]@{ Total = $total }
    foreach ($g in ($groups.Keys | Sort-Object)) { $o[$g] = $groups[$g] }
    if ($stopped) { $o['StoppedAtDeadline'] = $true }
    return $o
}

function Get-RecipientInventorySection {
    $out = [ordered]@{}
    $out.Note = 'Counts only. No recipient names, addresses or memberships are collected.'

    # --- Exchange cmdlet based counts ---------------------------------------------------
    # One forest-wide enumeration (Get-Recipient) is the primary source; the per-type cmdlets
    # (Get-Mailbox, Get-RemoteMailbox, ...) are only run when Get-Recipient was unavailable or
    # failed, which removes six further forest-wide enumerations from the normal path.
    $exCounts = [ordered]@{}
    $byType = $null
    if (Test-CmdletAvailable -Name 'Get-Recipient') {
        $exCounts.ByRecipientTypeDetails = Invoke-Guarded -What 'Get-Recipient' -Script {
            $o = Get-GroupedCountFromCmdlet -Cmdlet 'Get-Recipient'
            $o
        }
        if ($exCounts.ByRecipientTypeDetails -is [System.Collections.IDictionary] -and -not $exCounts.ByRecipientTypeDetails.Contains('StoppedAtDeadline')) { $byType = $exCounts.ByRecipientTypeDetails }
    }
    $mbxTypeNames = @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'LinkedMailbox', 'LegacyMailbox', 'LinkedRoomMailbox', 'TeamMailbox', 'GroupMailbox', 'SchedulingMailbox')
    $derived = [ordered]@{
        Mailboxes                 = @{ Types = $mbxTypeNames; Cmdlet = 'Get-Mailbox' }
        RemoteMailboxes           = @{ Types = @('RemoteUserMailbox', 'RemoteSharedMailbox', 'RemoteRoomMailbox', 'RemoteEquipmentMailbox', 'RemoteTeamMailbox', 'RemoteGroupMailbox'); Cmdlet = 'Get-RemoteMailbox' }
        MailUsers                 = @{ Types = @('MailUser', 'GuestMailUser'); Cmdlet = 'Get-MailUser' }
        MailContacts              = @{ Types = @('MailContact', 'CrossForestMailContact'); Cmdlet = 'Get-MailContact' }
        DistributionGroups        = @{ Types = @('MailUniversalDistributionGroup', 'MailUniversalSecurityGroup', 'MailNonUniversalGroup', 'RoomList'); Cmdlet = 'Get-DistributionGroup' }
        DynamicDistributionGroups = @{ Types = @('DynamicDistributionGroup'); Cmdlet = 'Get-DynamicDistributionGroup' }
        MailPublicFolders         = @{ Types = @('PublicFolder'); Cmdlet = 'Get-MailPublicFolder' }
    }
    foreach ($k in @($derived.Keys)) {
        $spec = $derived[$k]
        if ($null -ne $byType) {
            $o = [ordered]@{ Total = 0; DerivedFrom = 'Get-Recipient' }
            foreach ($t in $spec.Types) { if ($byType.Contains($t)) { $o[$t] = [int]$byType[$t]; $o.Total = $o.Total + [int]$byType[$t] } }
            $exCounts[$k] = $o
        }
        elseif (Test-CmdletAvailable -Name $spec.Cmdlet) {
            if (Test-PastDeadline) { $exCounts[$k] = 'skipped: deadline'; continue }
            $cmdName = $spec.Cmdlet
            $exCounts[$k] = Invoke-Guarded -What $cmdName -Script { Get-GroupedCountFromCmdlet -Cmdlet $cmdName }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-Mailbox') {
        # Special mailbox classes are small sets (arbitration, audit, monitoring, public folder,
        # migration, group). -Archive is the only potentially large one and runs last.
        foreach ($mbxSwitch in @('Arbitration', 'AuditLog', 'AuxAuditLog', 'Monitoring', 'PublicFolder', 'Migration', 'GroupMailbox', 'Archive')) {
            if (-not (Test-CmdletParameter -Cmdlet 'Get-Mailbox' -Parameter $mbxSwitch)) { continue }
            if (Test-PastDeadline) { $exCounts["Special_$mbxSwitch"] = 'skipped: deadline'; continue }
            $sw = $mbxSwitch
            $exCounts["Special_$mbxSwitch"] = Invoke-Guarded -What "Get-Mailbox -$mbxSwitch" -Script {
                $extra = @{}; $extra[$sw] = $true
                $g = Get-GroupedCountFromCmdlet -Cmdlet 'Get-Mailbox' -ExtraParams $extra
                if ($g.Contains('StoppedAtDeadline')) { "$($g.Total)+ (stopped at deadline)" } else { [int]$g.Total }
            }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-PublicFolder') {
        # Top-level public folders only (finding 21): -Recurse on a legacy 2010 hierarchy takes
        # hours. Public folder databases, PF mailboxes and the AD PublicFolderMailbox count are
        # the signals that matter; this confirms whether a hierarchy exists at all.
        $exCounts.PublicFolderTopLevelCount = Invoke-Guarded -What 'Get-PublicFolder (top level)' -Script {
            $p = @{ Identity = '\'; GetChildren = $true; ErrorAction = 'Stop' }
            if (Test-CmdletParameter -Cmdlet 'Get-PublicFolder' -Parameter 'ResultSize') { $p['ResultSize'] = 1000 }
            if ((Test-CmdletParameter -Cmdlet 'Get-PublicFolder' -Parameter 'Server') -and $script:Ctx.ExchangeVersionKey -eq 'v14') { $p['Server'] = $env:COMPUTERNAME }
            @(Get-PublicFolder @p | Select-Object -Property Identity).Count
        }
    }
    if (Test-CmdletAvailable -Name 'Get-EmailAddressPolicy') {
        $exCounts.EmailAddressPolicies = Invoke-Guarded -What 'Get-EmailAddressPolicy' -Script {
            @(Get-EmailAddressPolicy -ErrorAction Stop | ForEach-Object {
                $e = Select-SafeProperties -InputObject $_ -Properties @('Name', 'Priority', 'Enabled', 'IncludedRecipients', 'RecipientFilterType', 'EnabledPrimarySMTPAddressTemplate') -HostnameProperties @('Name')
                if ("$($_.Name)" -eq 'Default Policy') { $e['Name'] = 'Default Policy' }
                if ($e.Contains('EnabledPrimarySMTPAddressTemplate')) { $e['EnabledPrimarySMTPAddressTemplate'] = Protect-Hostname -Value "$($e['EnabledPrimarySMTPAddressTemplate'])" }
                $e
            })
        }
    }
    if (Test-CmdletAvailable -Name 'Get-AddressList') { $exCounts.AddressListCount = Invoke-Guarded -What 'Get-AddressList' -Script { @(Get-AddressList -ErrorAction Stop).Count } }
    if (Test-CmdletAvailable -Name 'Get-GlobalAddressList') { $exCounts.GlobalAddressListCount = Invoke-Guarded -What 'Get-GlobalAddressList' -Script { @(Get-GlobalAddressList -ErrorAction Stop).Count } }
    if (Test-CmdletAvailable -Name 'Get-OfflineAddressBook') { $exCounts.OfflineAddressBookCount = Invoke-Guarded -What 'Get-OfflineAddressBook' -Script { @(Get-OfflineAddressBook -ErrorAction Stop).Count } }
    if (Test-CmdletAvailable -Name 'Get-MoveRequest') { $exCounts.MoveRequestCount = Invoke-Guarded -What 'Get-MoveRequest' -Script { @(Get-MoveRequest -ResultSize 5000 -ErrorAction Stop | Select-Object -Property Status).Count } }
    if (Test-CmdletAvailable -Name 'Get-MigrationBatch') { $exCounts.MigrationBatchCount = Invoke-Guarded -What 'Get-MigrationBatch' -Script { @(Get-MigrationBatch -ErrorAction Stop | Select-Object -Property Status).Count } }

    $out.FromExchangeCmdlets = $exCounts
    $out.ExchangeCmdletsUsed = ($exCounts.Count -gt 0)

    # --- AD based counts (always attempted; the fallback when no tools are available) ----
    if ($script:Ctx.IsDomainJoined) {
        $out.FromActiveDirectory = Invoke-Guarded -What 'AD recipient counts' -Script { Get-RecipientCountFromAd }
    }
    else { $out.FromActiveDirectory = [ordered]@{ Note = 'Not domain-joined.' } }

    # --- Headline numbers ---------------------------------------------------------------
    $userMbx = $null; $source = 'none'
    $mbxTypes = @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'LinkedMailbox', 'LegacyMailbox')
    $onPremMbxTotal = $null
    if ($exCounts.Contains('Mailboxes') -and $exCounts.Mailboxes -is [System.Collections.IDictionary] -and -not $exCounts.Mailboxes.Contains('StoppedAtDeadline')) {
        $m = $exCounts.Mailboxes
        $userMbx = 0; if ($m.Contains('UserMailbox')) { $userMbx = [int]$m['UserMailbox'] }
        $onPremMbxTotal = 0; foreach ($t in $mbxTypes) { if ($m.Contains($t)) { $onPremMbxTotal += [int]$m[$t] } }
        $source = $(if ($m.Contains('DerivedFrom')) { 'Exchange cmdlets (Get-Recipient)' } else { 'Exchange cmdlets (Get-Mailbox)' })
    }
    elseif ($out.FromActiveDirectory -is [System.Collections.IDictionary] -and $out.FromActiveDirectory.Contains('Counts')) {
        $c = $out.FromActiveDirectory.Counts
        $userMbx = 0; if ($c.Contains('UserMailbox')) { $userMbx = [int]$c['UserMailbox'] }
        $onPremMbxTotal = 0; foreach ($t in $mbxTypes) { if ($c.Contains($t)) { $onPremMbxTotal += [int]$c[$t] } }
        $source = 'Active Directory (msExchRecipientTypeDetails)'
    }
    $remoteTotal = $null
    if ($exCounts.Contains('RemoteMailboxes') -and $exCounts.RemoteMailboxes -is [System.Collections.IDictionary] -and -not $exCounts.RemoteMailboxes.Contains('StoppedAtDeadline')) { $remoteTotal = $exCounts.RemoteMailboxes.Total }
    elseif ($out.FromActiveDirectory -is [System.Collections.IDictionary] -and $out.FromActiveDirectory.Contains('Counts')) {
        $remoteTotal = 0
        foreach ($t in @('RemoteUserMailbox', 'RemoteSharedMailbox', 'RemoteRoomMailbox', 'RemoteEquipmentMailbox', 'RemoteTeamMailbox', 'RemoteGroupMailbox')) { if ($out.FromActiveDirectory.Counts.Contains($t)) { $remoteTotal += [int]$out.FromActiveDirectory.Counts[$t] } }
    }
    $out.Headline = [ordered]@{
        OnPremUserMailboxCount      = $userMbx
        OnPremMailboxCountAllTypes  = $onPremMbxTotal
        RemoteMailboxCount          = $remoteTotal
        Source                      = $source
        Interpretation              = 'OnPremUserMailboxCount must be 0 (and no public folder content on-premises) for the standalone Exchange Management Tools option.'
    }
    $script:Ctx.OnPremUserMailboxCount = $userMbx
    $script:Ctx.OnPremMailboxCountAllTypes = $onPremMbxTotal
    $script:Ctx.RemoteMailboxCount = $remoteTotal
    $script:Ctx.RecipientCountSource = $source
    return $out
}

# =======================================================================================
# SECTION F - Hybrid configuration
# =======================================================================================
function Get-HybridSection {
    $out = [ordered]@{}

    if (Test-CmdletAvailable -Name 'Get-HybridConfiguration') {
        $out.HybridConfiguration = Invoke-Guarded -What 'Get-HybridConfiguration' -Script {
            $h = Get-HybridConfiguration -ErrorAction Stop
            if ($null -eq $h) { return ([ordered]@{ Present = $false }) }
            $hc = Select-SafeProperties -InputObject $h -Properties @('Name', 'Features', 'Domains', 'OnPremisesSmartHost', 'SendingTransportServers', 'ReceivingTransportServers', 'EdgeTransportServers', 'ClientAccessServers', 'ExternalIPAddresses', 'ServiceInstance', 'WhenChanged', 'WhenCreated', 'ObjectVersion', 'ExchangeVersion') -HostnameProperties @('Domains', 'OnPremisesSmartHost', 'SendingTransportServers', 'ReceivingTransportServers', 'EdgeTransportServers', 'ClientAccessServers')
            $hc['Present'] = $true
            $tls = "$(Get-PropertySafe -InputObject $h -Name 'TlsCertificateName')"
            $tlsSubject = $null; if ($tls -match '<S>CN=([^,]+)') { $tlsSubject = $Matches[1] }
            $tlsIssuer  = $null; if ($tls -match '<I>CN=([^,]+)') { $tlsIssuer = $Matches[1] }
            $hc['TlsCertificateSubjectCN'] = Protect-Hostname -Value $tlsSubject
            $hc['TlsCertificateIssuerCN']  = Protect-CertificateIssuer -IssuerCN $tlsIssuer
            $hc['TlsCertificateIssuerIsPublicCA'] = Test-PublicCertificateAuthority -IssuerCN $tlsIssuer
            $hc
        }
    }
    else { $out.HybridConfiguration = [ordered]@{ Present = $null; Note = (Get-CmdletUnavailableNote -Cmdlet 'Get-HybridConfiguration') + ' (also absent on Exchange 2010 before SP2). See HybridObjectInAd.' } }

    # AD fallback: the hybrid configuration object lives in the config partition.
    if ($script:Ctx.IsDomainJoined -and $script:Ctx.ExchangeOrgDn) {
        $out.HybridObjectInAd = Invoke-Guarded -What 'Hybrid object in AD' -Script {
            $rows = @(Search-Directory -SearchBase ("LDAP://" + $script:Ctx.ExchangeOrgDn) -Filter '(objectClass=msExchCoexistenceRelationship)' -Properties @('name', 'whenChanged', 'whenCreated', 'msExchCoexistenceFeatureFlags', 'msExchCoexistenceDomains') -Scope 'Subtree' -TimeoutSeconds 60)
            if ($rows.Count -eq 0) { return ([ordered]@{ Present = $false }) }
            [ordered]@{ Present = $true; Count = $rows.Count; WhenChanged = (ConvertTo-IsoString -Value $rows[0].whenChanged); WhenCreated = (ConvertTo-IsoString -Value $rows[0].whenCreated); FeatureFlags = $rows[0].msExchCoexistenceFeatureFlags; DomainCount = (Get-SafeCount -Value $rows[0].msExchCoexistenceDomains) }
        }
    }

    # Hybrid Configuration Wizard presence (ClickOnce install, per-user) and its logs
    $out.HybridConfigurationWizard = Invoke-Guarded -What 'HCW presence' -Script {
        $progs = @(Get-InstalledProgramList | Where-Object { "$($_.DisplayName)" -match 'Hybrid Configuration Wizard' })
        $logDir = $null; $logCount = 0; $newest = $null
        if ($env:APPDATA) {
            $logDir = Join-Path $env:APPDATA 'Microsoft\Exchange Hybrid Configuration'
            if (Test-Path -LiteralPath $logDir) {
                $files = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue)
                $logCount = $files.Count
                if ($files.Count -gt 0) { $newest = ConvertTo-IsoString -Value (($files | Sort-Object LastWriteTime -Descending)[0].LastWriteTime) }
            }
        }
        [ordered]@{
            InstalledForCurrentUser = ($progs.Count -gt 0)
            Version                 = $(if ($progs.Count -gt 0) { "$($progs[0].DisplayVersion)" } else { $null })
            LogFolderPresentForCurrentUser = ($logCount -gt 0)
            LogFileCount            = $logCount
            NewestLogWrite          = $newest
            Note                    = 'HCW is installed per user; a different admin account may hold the install and logs.'
        }
    }

    # Hybrid Agent (Modern Hybrid)
    $out.HybridAgent = Invoke-Guarded -What 'Hybrid Agent' -Script {
        $svc = @(Get-CimSafe -Class 'Win32_Service' -Filter "DisplayName LIKE '%Hybrid Service%' OR Name LIKE '%HybridSvc%' OR Name LIKE '%Hybrid Service%'")
        $prog = @(Get-InstalledProgramList | Where-Object { "$($_.DisplayName)" -match '^Microsoft Hybrid Service' })
        $dir  = Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Microsoft Hybrid Service')
        [ordered]@{
            ServicePresent   = ($svc.Count -gt 0)
            ServiceState     = $(if ($svc.Count -gt 0) { "$($svc[0].State)" } else { $null })
            ProgramInstalled = ($prog.Count -gt 0)
            ProgramVersion   = $(if ($prog.Count -gt 0) { "$($prog[0].DisplayVersion)" } else { $null })
            InstallFolderPresent = $dir
        }
    }

    $mode = 'None detected'
    if ($out.HybridAgent -is [System.Collections.IDictionary] -and ($out.HybridAgent.ServicePresent -or $out.HybridAgent.ProgramInstalled)) { $mode = 'Modern (Hybrid Agent) on this host' }
    elseif ($out.HybridConfiguration -is [System.Collections.IDictionary] -and $out.HybridConfiguration.Present -eq $true) { $mode = 'Classic (published endpoints) or Modern with the agent on another host' }
    elseif ($out.HybridObjectInAd -is [System.Collections.IDictionary] -and $out.HybridObjectInAd.Present -eq $true) { $mode = 'Hybrid object present in AD (tools unavailable to read detail)' }
    $out.HybridMode = $mode
    $script:Ctx.HybridConfigured = ($mode -ne 'None detected')
    $script:Ctx.HybridMode = $mode

    # Federation / OAuth / relationships
    $cmdMap = [ordered]@{
        OrganizationRelationships   = @{ Cmd = 'Get-OrganizationRelationship'; Props = @('Name', 'DomainNames', 'Enabled', 'FreeBusyAccessEnabled', 'FreeBusyAccessLevel', 'MailboxMoveEnabled', 'MailboxMoveCapability', 'TargetApplicationUri', 'TargetAutodiscoverEpr', 'TargetOwaURL', 'TargetSharingEpr', 'OrganizationContact', 'ArchiveAccessEnabled', 'PhotosEnabled'); Hosts = @('Name', 'DomainNames', 'TargetApplicationUri'); Urls = @('TargetAutodiscoverEpr', 'TargetOwaURL', 'TargetSharingEpr'); Accounts = @('OrganizationContact') }
        FederationTrusts            = @{ Cmd = 'Get-FederationTrust'; Props = @('Name', 'ApplicationIdentifier', 'ApplicationUri', 'TokenIssuerUri', 'TokenIssuerType', 'OrgCertificate', 'TokenIssuerMetadataEpr'); Hosts = @('Name', 'ApplicationUri'); Urls = @('TokenIssuerUri', 'TokenIssuerMetadataEpr'); Accounts = @() }
        FederatedOrganizationIdentifier = @{ Cmd = 'Get-FederatedOrganizationIdentifier'; Props = @('AccountNamespace', 'Domains', 'Enabled', 'DefaultDomain', 'DelegationTrustLink'); Hosts = @('AccountNamespace', 'Domains', 'DefaultDomain', 'DelegationTrustLink'); Urls = @(); Accounts = @() }
        IntraOrganizationConnectors = @{ Cmd = 'Get-IntraOrganizationConnector'; Props = @('Name', 'TargetAddressDomains', 'DiscoveryEndpoint', 'Enabled'); Hosts = @('Name', 'TargetAddressDomains'); Urls = @('DiscoveryEndpoint'); Accounts = @() }
        AuthServers                 = @{ Cmd = 'Get-AuthServer'; Props = @('Name', 'Type', 'IssuerIdentifier', 'Realm', 'Enabled', 'IsDefaultAuthorizationEndpoint', 'AuthorizationEndpoint', 'TokenIssuingEndpoint', 'AuthMetadataUrl', 'DomainName'); Hosts = @('Name', 'DomainName'); Urls = @('AuthorizationEndpoint', 'TokenIssuingEndpoint', 'AuthMetadataUrl'); Accounts = @() }
        PartnerApplications         = @{ Cmd = 'Get-PartnerApplication'; Props = @('Name', 'Enabled', 'ApplicationIdentifier', 'AuthMetadataUrl', 'UseAuthServer', 'AcceptSecurityIdentifierInformation'); Hosts = @('Name'); Urls = @('AuthMetadataUrl'); Accounts = @() }
        AvailabilityAddressSpaces   = @{ Cmd = 'Get-AvailabilityAddressSpace'; Props = @('ForestName', 'AccessMethod', 'UseServiceAccount', 'ProxyUrl', 'TargetAutodiscoverEpr'); Hosts = @('ForestName'); Urls = @('ProxyUrl', 'TargetAutodiscoverEpr'); Accounts = @() }
    }
    foreach ($k in $cmdMap.Keys) {
        $m = $cmdMap[$k]
        $cmdName = "$($m.Cmd)"
        if (-not (Test-CmdletAvailable -Name $cmdName)) { $out[$k] = Get-CmdletUnavailableNote -Cmdlet $cmdName; continue }
        if (Test-PastDeadline) { $out[$k] = 'skipped: deadline'; continue }
        $out[$k] = Invoke-Guarded -What $cmdName -Script {
            @(& $cmdName -ErrorAction Stop | ForEach-Object {
                $o = Select-SafeProperties -InputObject $_ -Properties $m.Props -HostnameProperties $m.Hosts -UrlProperties $m.Urls -AccountProperties $m.Accounts
                if ($o.Contains('OrgCertificate')) { $o['OrgCertificate'] = $(if ($o['OrgCertificate']) { 'present' } else { $null }) }
                $o
            })
        }
    }
    if (Test-CmdletAvailable -Name 'Get-AuthConfig') {
        $out.AuthConfig = Invoke-Guarded -What 'Get-AuthConfig' -Script {
            $a = Get-AuthConfig -ErrorAction Stop
            [ordered]@{
                ServiceName = "$(Get-PropertySafe -InputObject $a -Name 'ServiceName')"
                Realm       = "$(Get-PropertySafe -InputObject $a -Name 'Realm')"
                CurrentCertificateThumbprintPrefix = "$(Get-PropertySafe -InputObject $a -Name 'CurrentCertificateThumbprint')".Substring(0, [math]::Min(8, "$(Get-PropertySafe -InputObject $a -Name 'CurrentCertificateThumbprint')".Length))
                NextCertificateThumbprintPrefix    = "$(Get-PropertySafe -InputObject $a -Name 'NextCertificateThumbprint')".Substring(0, [math]::Min(8, "$(Get-PropertySafe -InputObject $a -Name 'NextCertificateThumbprint')".Length))
            }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-MigrationEndpoint') {
        $out.MigrationEndpoints = Invoke-Guarded -What 'Get-MigrationEndpoint' -Script {
            $eps = @(Get-MigrationEndpoint -ErrorAction Stop)
            [ordered]@{ Count = $eps.Count; Endpoints = @(foreach ($e in $eps) { [ordered]@{ Identity = (Protect-Hostname -Value "$($e.Identity)"); EndpointType = "$($e.EndpointType)"; RemoteServer = (Protect-Hostname -Value "$($e.RemoteServer)"); MaxConcurrentMigrations = $e.MaxConcurrentMigrations; IsRemote = (Get-PropertySafe -InputObject $e -Name 'IsRemote') } }) }
        }
    }
    if (Test-CmdletAvailable -Name 'Get-OrganizationConfig') {
        $out.OrganizationConfig = Invoke-Guarded -What 'Get-OrganizationConfig' -Script {
            $oc = Get-OrganizationConfig -ErrorAction Stop
            $o = Select-SafeProperties -InputObject $oc -Properties @('Name', 'ExchangeVersion', 'AdminDisplayVersion', 'OAuth2ClientProfileEnabled', 'MapiHttpEnabled', 'PublicFoldersEnabled', 'PublicFolderMigrationComplete', 'PublicFoldersLockedForMigration', 'IsMixedMode', 'ACLableSyncedObjectEnabled', 'WACDiscoveryEndpoint', 'IsDehydrated', 'MailTipsAllTipsEnabled') -HostnameProperties @('Name') -UrlProperties @('WACDiscoveryEndpoint')
            # RemotePublicFolderMailboxes does not exist on Exchange 2010; Get-SafeCount keeps the
            # missing property at 0 rather than the phantom 1 that @($null).Count produces.
            $rpf = Get-PropertySafe -InputObject $oc -Name 'RemotePublicFolderMailboxes'
            $o['RemotePublicFolderMailboxPropertyPresent'] = ($null -ne $oc.PSObject.Properties['RemotePublicFolderMailboxes'])
            $o['RemotePublicFolderMailboxCount'] = Get-SafeCount -Value $rpf
            $o['HierarchicalAddressBookRootSet'] = ($null -ne (Get-PropertySafe -InputObject $oc -Name 'HierarchicalAddressBookRoot'))
            $o['DistributionGroupNamingPolicySet'] = -not [string]::IsNullOrWhiteSpace("$(Get-PropertySafe -InputObject $oc -Name 'DistributionGroupNamingPolicy')")
            $o
        }
    }

    # Coexistence / target delivery domain from accepted domains (tenant identifier)
    $out.TenantIndicators = Invoke-Guarded -What 'Tenant indicators' -Script {
        $t = [ordered]@{ CoexistenceDomain = $null; OnMicrosoftDomains = @(); TargetDeliveryDomainFromRemoteDomains = $null }
        if (Test-CmdletAvailable -Name 'Get-AcceptedDomain') {
            foreach ($d in @(Get-AcceptedDomain -ErrorAction Stop)) {
                $dn = "$($d.DomainName)"
                if ($dn -like '*.mail.onmicrosoft.com') { $t.CoexistenceDomain = Protect-Hostname -Value $dn }
                if ($dn -like '*.onmicrosoft.com') { $t.OnMicrosoftDomains += (Protect-Hostname -Value $dn) }
            }
        }
        if (Test-CmdletAvailable -Name 'Get-RemoteDomain') {
            foreach ($r in @(Get-RemoteDomain -ErrorAction Stop)) { if ((Get-PropertySafe -InputObject $r -Name 'TargetDeliveryDomain') -eq $true) { $t.TargetDeliveryDomainFromRemoteDomains = Protect-Hostname -Value "$($r.DomainName)" } }
        }
        if (-not $t.CoexistenceDomain -and $script:Ctx.IsDomainJoined -and $script:Ctx.ExchangeOrgDn) {
            $rows = @(Search-Directory -SearchBase ("LDAP://" + $script:Ctx.ExchangeOrgDn) -Filter '(&(objectClass=msExchAcceptedDomain)(msExchAcceptedDomainName=*.onmicrosoft.com))' -Properties @('msExchAcceptedDomainName') -Scope 'Subtree' -TimeoutSeconds 60)
            foreach ($r in $rows) {
                $dn = "$($r.msExchAcceptedDomainName)"
                if ($dn -like '*.mail.onmicrosoft.com') { $t.CoexistenceDomain = Protect-Hostname -Value $dn }
                if ($dn -like '*.onmicrosoft.com') { $t.OnMicrosoftDomains += (Protect-Hostname -Value $dn) }
            }
            $t.Source = 'Active Directory'
        }
        $t
    }
    return $out
}

# =======================================================================================
# SECTION K - Licensing posture signals
# =======================================================================================
function Get-LicensingSection {
    $out = [ordered]@{}
    $out.DetectedProduct = $script:Ctx.ExchangeProduct
    $out.DetectedVersionString = $script:Ctx.ExchangeVersionString
    if (Test-CmdletAvailable -Name 'Get-ExchangeServer') {
        $out.Servers = Invoke-Guarded -What 'Get-ExchangeServer licensing' -Script {
            @(Get-ExchangeServer -ErrorAction Stop | ForEach-Object {
                $s = Select-SafeProperties -InputObject $_ -Properties @('Name', 'Edition', 'ProductID', 'IsExchangeTrialEdition', 'RemainingTrialPeriod', 'IsHybridServer', 'AdminDisplayVersion', 'ServerRole') -HostnameProperties @('Name')
                $s['LikelyHybridKey'] = ("$($_.Edition)" -match 'Coexistence')
                $s['LikelyUnlicensedTrial'] = ("$($_.Edition)" -match 'Evaluation' -or "$(Get-PropertySafe -InputObject $_ -Name 'IsExchangeTrialEdition')" -eq 'True')
                $s
            })
        }
    }
    else { $out.Servers = (Get-CmdletUnavailableNote -Cmdlet 'Get-ExchangeServer') + ' See ExchangeDetection.ActiveDirectory.Servers for ProductId per server.' }
    $out.OrganisationVersionSpan = [ordered]@{
        OldestServer = $script:Ctx.OrgMinProduct
        NewestServer = $script:Ctx.OrgMaxProduct
        ServerCountByFamily = $script:Ctx.OrgServerCountByFamily
        Note = 'Support and coexistence decisions are driven by the oldest server in the organisation, not by this host.'
    }
    if (Test-CmdletAvailable -Name 'Get-ExchangeServerAccessLicense') {
        $out.AccessLicenses = Invoke-Guarded -What 'Get-ExchangeServerAccessLicense' -Script { @(Get-ExchangeServerAccessLicense -ErrorAction Stop | ForEach-Object { "$($_.LicenseName)" }) }
    }
    $osCaption = $null
    try { $osCaption = $script:Sections['Host'].OperatingSystem.Caption } catch { }
    $out.SubscriptionEditionReadiness = [ordered]@{
        OsCaption                  = $osCaption
        OsSupportedForSE           = $(if ($osCaption -match '2019|2022|2025') { $true } elseif ($osCaption) { $false } else { $null })
        DotNetFramework            = $(try { $script:Sections['Host'].DotNetFramework.FriendlyName } catch { $null })
        InPlaceUpgradeToSEPossible = $(if ($script:Ctx.ExchangeProduct -match '2019 CU1[45]') { 'Yes (2019 CU14/CU15 -> SE in-place)' } elseif ($script:Ctx.ExchangeProduct -match 'Subscription Edition') { 'Already SE' } elseif ($script:Ctx.ExchangeProduct -match '2019') { 'Update to CU15 first' } elseif ($script:Ctx.ExchangeProduct) { 'No - legacy (new server) upgrade required' } else { 'Unknown' })
        Note                       = 'Exchange SE requires a subscription or Software Assurance; a hybrid (free) key entitles only a server with no on-premises mailboxes.'
    }
    return $out
}

# =======================================================================================
# SECTION G - Entra Connect (Azure AD Connect / ADConnect)
# =======================================================================================
function Get-EntraConnectSection {
    $out = [ordered]@{}

    $svc = @(Get-CimSafe -Class 'Win32_Service' -Filter "Name='ADSync'")
    $prog = @(Get-InstalledProgramList | Where-Object { "$($_.DisplayName)" -match 'Azure AD Connect|Entra Connect|Azure Active Directory Connect' -and "$($_.DisplayName)" -notmatch 'Health|Authentication Agent|Provisioning' })
    $regVersion = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Azure AD Connect' -Name 'WizardPath'
    $adSyncModule = Get-Module -ListAvailable -Name ADSync -ErrorAction SilentlyContinue | Select-Object -First 1
    $onThisHost = ($svc.Count -gt 0 -or $prog.Count -gt 0)
    $out.InstalledOnThisHost = $onThisHost
    $out.DeterminedBy = 'ADSync service presence, installed-program registry entries and the ADSync PowerShell module.'
    $out.AdSyncService = $(if ($svc.Count -gt 0) { [ordered]@{ State = "$($svc[0].State)"; StartMode = "$($svc[0].StartMode)"; RunAs = (Protect-Account -Value "$($svc[0].StartName)"); ExePath = (Protect-FilePath -Value "$($svc[0].PathName)") } } else { $null })
    $out.InstalledProgram = $(if ($prog.Count -gt 0) { [ordered]@{ DisplayName = "$($prog[0].DisplayName)"; Version = "$($prog[0].DisplayVersion)"; InstallDate = "$($prog[0].InstallDate)" } } else { $null })
    $out.WizardPathRegistered = ($null -ne $regVersion)
    $out.AdSyncModuleVersion = $(if ($adSyncModule) { "$($adSyncModule.Version)" } else { $null })
    $out.MiiserverFileVersion = Invoke-Guarded -What 'miiserver version' -Script {
        if ($svc.Count -gt 0 -and "$($svc[0].PathName)" -match '^"?([^"]+miiserver\.exe)') { "$((Get-Item -LiteralPath $Matches[1] -ErrorAction Stop).VersionInfo.FileVersion)" } else { $null }
    }

    # Related agents on this host
    $out.RelatedAgents = Invoke-Guarded -What 'Related agents' -Script {
        $agents = @(Get-CimSafe -Class 'Win32_Service' -Filter "Name='AzureADConnectAuthenticationAgent' OR Name='AzureADConnectHealthSyncInsights' OR Name='AzureADConnectHealthSyncMonitor' OR Name='adfssrv' OR Name LIKE 'AADConnectProvisioningAgent%' OR DisplayName LIKE '%Provisioning Agent%' OR Name='drs'")
        @(foreach ($a in $agents) { [ordered]@{ Name = $a.Name; DisplayName = $a.DisplayName; State = $a.State; StartMode = $a.StartMode } })
    }
    $ptaAgentPresent = [bool](@($out.RelatedAgents | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['Name'] -eq 'AzureADConnectAuthenticationAgent' }).Count -gt 0)
    $adfsPresent = [bool](@($out.RelatedAgents | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['Name'] -eq 'adfssrv' }).Count -gt 0)

    if ($onThisHost) {
        $moduleLoaded = $false
        try { Import-Module ADSync -ErrorAction Stop -WarningAction SilentlyContinue; $moduleLoaded = $true } catch { Write-SectionWarning -Message ('ADSync module could not be loaded (needs local ADSyncAdmins membership or elevation): ' + (ConvertTo-SafeError -ErrorRecord $_)) }
        $out.AdSyncModuleLoaded = $moduleLoaded
        if ($moduleLoaded) {
            if (Test-CmdletAvailable -Name 'Get-ADSyncScheduler') {
                $out.Scheduler = Invoke-Guarded -What 'Get-ADSyncScheduler' -Script {
                    Select-SafeProperties -InputObject (Get-ADSyncScheduler -ErrorAction Stop) -Properties @('AllowedSyncCycleInterval', 'CurrentlyEffectiveSyncCycleInterval', 'CustomizedSyncCycleInterval', 'NextSyncCyclePolicyType', 'NextSyncCycleStartTimeInUTC', 'PurgeRunHistoryInterval', 'SyncCycleEnabled', 'MaintenanceEnabled', 'StagingModeEnabled', 'SchedulerSuspended', 'SyncCycleInProgress')
                }
            }
            if (Test-CmdletAvailable -Name 'Get-ADSyncGlobalSettings') {
                $out.GlobalSettingsParameters = Invoke-Guarded -What 'Get-ADSyncGlobalSettings' -Script {
                    $gs = Get-ADSyncGlobalSettings -ErrorAction Stop
                    $p = [ordered]@{}
                    foreach ($param in @($gs.Parameters)) {
                        $n = "$($param.Name)"
                        if ($n -match 'Credential|Secret|Password\.|Key$|Token') { continue }
                        if ($n -match '^Microsoft\.(OptionalFeature|Synchronize|SystemInformation|AADPasswordSync|DeviceWriteBack|GroupWriteBack|UserWriteBack|Connector\.GroupFilter|DirectoryExtension|ExchangeMailPublicFolders)') { $p[$n] = "$($param.Value)" }
                    }
                    $p
                }
                $out.ExchangeHybridWritebackEnabled = Invoke-Guarded -What 'Exchange hybrid writeback flag' -Script {
                    $flag = $null
                    foreach ($k in @($out.GlobalSettingsParameters.Keys)) { if ($k -match 'Exchange.*Hybrid|Hybrid.*Exchange') { $flag = ("$($out.GlobalSettingsParameters[$k])" -eq 'True') } }
                    $flag
                }
                $out.PasswordHashSyncEnabled = Invoke-Guarded -What 'PHS flag' -Script {
                    $flag = $null
                    foreach ($k in @($out.GlobalSettingsParameters.Keys)) { if ($k -match 'PasswordHashSync|PasswordSync') { $flag = ("$($out.GlobalSettingsParameters[$k])" -eq 'True') } }
                    $flag
                }
            }
            if (Test-CmdletAvailable -Name 'Get-ADSyncAADCompanyFeature') {
                $out.TenantFeatures = Invoke-Guarded -What 'Get-ADSyncAADCompanyFeature' -Script {
                    $f = Get-ADSyncAADCompanyFeature -ErrorAction Stop
                    $o = [ordered]@{}
                    foreach ($prop in $f.PSObject.Properties) { if ($prop.Value -is [bool] -or $prop.Value -is [string]) { $o[$prop.Name] = ConvertTo-SafeValue -Value $prop.Value } }
                    $o
                }
            }
            if (Test-CmdletAvailable -Name 'Get-ADSyncConnector') {
                $out.Connectors = Invoke-Guarded -What 'Get-ADSyncConnector' -Script {
                    # Only names, types and OU-scope counts are read; connectivity parameters
                    # (which contain the sync account name and secret) are never touched.
                    @(Get-ADSyncConnector -ErrorAction Stop | ForEach-Object {
                        $c = $_
                        $incl = $null; $excl = $null; $partitions = 0
                        try {
                            $partitions = Get-SafeCount -Value (Get-PropertySafe -InputObject $c -Name 'Partitions')
                            $incl = 0; $excl = 0
                            foreach ($pt in @($c.Partitions)) {
                                try { $incl += Get-SafeCount -Value $pt.ConnectorPartitionScope.ContainerInclusionList; $excl += Get-SafeCount -Value $pt.ConnectorPartitionScope.ContainerExclusionList } catch { }
                            }
                        }
                        catch { }
                        [ordered]@{
                            Name              = Protect-Hostname -Value "$($c.Name)"
                            Type              = "$(Get-PropertySafe -InputObject $c -Name 'ConnectorTypeName')"
                            Subtype           = "$(Get-PropertySafe -InputObject $c -Name 'Subtype')"
                            PartitionCount    = $partitions
                            IncludedOUCount   = $incl
                            ExcludedOUCount   = $excl
                            ObjectInclusionCount = Get-SafeCount -Value (Get-PropertySafe -InputObject $c -Name 'ObjectInclusionList')
                        }
                    })
                }
                $out.ConnectorCount = Get-SafeCount -Value $out.Connectors
            }
            if (Test-CmdletAvailable -Name 'Get-ADSyncAutoUpgrade') { $out.AutoUpgrade = Invoke-Guarded -What 'Get-ADSyncAutoUpgrade' -Script { "$(Get-ADSyncAutoUpgrade -ErrorAction Stop)" } }
            if (Test-CmdletAvailable -Name 'Get-ADSyncExportDeletionThreshold') { $out.ExportDeletionThreshold = Invoke-Guarded -What 'Get-ADSyncExportDeletionThreshold' -Script { Select-SafeProperties -InputObject (Get-ADSyncExportDeletionThreshold -ErrorAction Stop) -Properties @('DeletionThresholdEnabled', 'DeletionThresholdValue') } }
            if (Test-CmdletAvailable -Name 'Get-ADSyncConnectorRunStatus') { $out.RunInProgress = Invoke-Guarded -What 'Get-ADSyncConnectorRunStatus' -Script { @(Get-ADSyncConnectorRunStatus -ErrorAction Stop).Count -gt 0 } }
            if (Test-CmdletAvailable -Name 'Get-ADSyncRunProfileResult') {
                $out.LastRuns = Invoke-Guarded -What 'Get-ADSyncRunProfileResult' -Script {
                    @(Get-ADSyncRunProfileResult -ErrorAction Stop | Sort-Object StartDate -Descending | Select-Object -First 6 | ForEach-Object {
                        [ordered]@{ Connector = (Protect-Hostname -Value "$(Get-PropertySafe -InputObject $_ -Name 'ConnectorName')"); RunProfile = "$(Get-PropertySafe -InputObject $_ -Name 'RunProfileName')"; Start = (ConvertTo-IsoString -Value (Get-PropertySafe -InputObject $_ -Name 'StartDate')); End = (ConvertTo-IsoString -Value (Get-PropertySafe -InputObject $_ -Name 'EndDate')); Result = "$(Get-PropertySafe -InputObject $_ -Name 'Result')" }
                    })
                }
            }
        }
        $out.LastDirectorySyncEvent = Invoke-Guarded -What 'Directory Synchronization event log' -Script {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Directory Synchronization' } -MaxEvents 1 -ErrorAction Stop
            if ($ev) { [ordered]@{ TimeCreated = (ConvertTo-IsoString -Value $ev.TimeCreated); Id = $ev.Id; Level = "$($ev.LevelDisplayName)" } } else { $null }
        }
        $out.RecentSyncErrorCount24h = Invoke-Guarded -What 'Sync error count' -Script {
            @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Directory Synchronization'; Level = 2; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue).Count
        }
    }
    else {
        $out.Note = 'Entra Connect is not installed on this host (no ADSync service, no installed-program entry).'
    }

    # Where does Entra Connect run? The MSOL_ sync account's description names the server and tenant.
    if ($script:Ctx.IsDomainJoined -and $script:Ctx.DefaultNC) {
        $out.SyncServerFromAd = Invoke-Guarded -What 'MSOL_ account description' -Script {
            $rows = @(Search-Directory -SearchBase ("LDAP://" + $script:Ctx.DefaultNC) -Filter '(&(objectClass=user)(sAMAccountName=MSOL_*))' -Properties @('sAMAccountName', 'description', 'whenCreated', 'userAccountControl') -Scope 'Subtree' -SizeLimit 10 -TimeoutSeconds 60)
            if ($rows.Count -eq 0) { return ([ordered]@{ Found = $false; Note = 'No MSOL_* account found. Entra Connect may use a gMSA/custom account, or run from another domain/forest.' }) }
            @(foreach ($r in $rows) {
                $desc = "$($r.description)"
                $server = $null; $tenant = $null
                if ($desc -match 'running on computer\s+''?([^''\s]+)''?') { $server = $Matches[1] }
                if ($desc -match 'synchronize to tenant\s+''?([^''\s.]+(?:\.[^''\s]+)*)''?') { $tenant = $Matches[1] }
                $uac = 0; try { $uac = [int]$r.userAccountControl } catch { }
                [ordered]@{
                    Found        = $true
                    Account      = Protect-Identifier -Value "$($r.sAMAccountName)"
                    SyncServer   = Protect-Hostname -Value $server
                    SyncServerIsThisHost = ($server -and ($server -ieq $env:COMPUTERNAME))
                    Tenant       = Protect-Hostname -Value $tenant
                    Created      = ConvertTo-IsoString -Value $r.whenCreated
                    AccountDisabled = (($uac -band 2) -ne 0)
                }
            })
        }
    }

    $signIn = 'Unknown (requires tenant query)'
    if ($out.Contains('PasswordHashSyncEnabled') -and $out.PasswordHashSyncEnabled -eq $true) { $signIn = 'Password hash sync enabled on this host' }
    if ($ptaAgentPresent) { $signIn = 'Pass-through authentication agent present on this host' }
    if ($adfsPresent) { $signIn = 'AD FS service present on this host (federated)' }
    if (-not $onThisHost -and -not $ptaAgentPresent -and -not $adfsPresent) { $signIn = 'Unknown - Entra Connect is not on this host' }
    $out.SignInMethodIndicator = $signIn
    $script:Ctx.EntraConnectOnThisHost = $onThisHost
    return $out
}

# =======================================================================================
# SECTION I - Automations: scheduled tasks, scripts, modules, service accounts
# =======================================================================================
# On-premises-only nouns: cmdlets with no Exchange Online equivalent. Every entry here must
# also be in ExchangeNouns or it can never be matched (finding 41). Covers the 2010 names
# (TransportServer, ClientAccessServer, PublicFolderDatabase, MailboxServer) and the 2016+
# names (ClientAccessService, TransportService, FrontendTransportService, MailboxTransportService).
$script:OnPremOnlyNouns = @('RemoteMailbox', 'ExchangeServer', 'ReceiveConnector', 'SendConnector', 'MailboxDatabase', 'MailboxDatabaseCopy',
    'MailboxDatabaseCopyStatus', 'DatabaseAvailabilityGroup', 'ADServerSettings', 'ExchangeCertificate', 'TransportServer', 'TransportService',
    'FrontendTransportService', 'MailboxTransportService', 'HybridConfiguration', 'ADPermission', 'MessageTrackingLog', 'Queue', 'Message',
    'OwaVirtualDirectory', 'EcpVirtualDirectory', 'WebServicesVirtualDirectory', 'ActiveSyncVirtualDirectory', 'OabVirtualDirectory',
    'AutodiscoverVirtualDirectory', 'MapiVirtualDirectory', 'PowerShellVirtualDirectory', 'OutlookAnywhere', 'ClientAccessServer',
    'ClientAccessService', 'ClientAccessArray', 'MailboxServer', 'PublicFolderDatabase', 'UMService', 'EdgeSubscription', 'EdgeSynchronization',
    'ExchangeServerAccessLicense', 'TransportAgent', 'ServerComponentState', 'ServerHealth', 'HealthReport', 'MailboxDatabaseCopy',
    'StoreUsageStatistics', 'ExchangeDiagnosticInfo', 'RpcClientAccess', 'ADSite', 'ADSiteLink', 'MailboxServer', 'DatabaseAvailabilityGroupNetwork',
    'ExchangeSettings', 'ExchangeFeature', 'PopSettings', 'ImapSettings', 'ReceiveConnector', 'SendConnector', 'ForeignConnector', 'DeliveryAgentConnector',
    'RoutingGroupConnector', 'TransportPipeline', 'MessageTrackingReport', 'AgentLog', 'MailboxRepairRequest', 'MailboxRestoreRequest', 'MailboxAuditBypassAssociation')
$script:ExchangeNouns = @('Mailbox', 'RemoteMailbox', 'MailUser', 'MailContact', 'DistributionGroup', 'DistributionGroupMember', 'DynamicDistributionGroup',
    'CASMailbox', 'MailboxPermission', 'RecipientPermission', 'MailboxFolderPermission', 'MailboxDatabase', 'MailboxStatistics', 'Recipient', 'MoveRequest',
    'MigrationBatch', 'MigrationUser', 'AcceptedDomain', 'EmailAddressPolicy', 'AddressList', 'TransportRule', 'ReceiveConnector', 'SendConnector',
    'ExchangeServer', 'MailboxAutoReplyConfiguration', 'MailboxRegionalConfiguration', 'CalendarProcessing', 'InboxRule', 'MailboxJunkEmailConfiguration',
    'UnifiedGroup', 'OrganizationConfig', 'HybridConfiguration', 'MailboxExportRequest', 'MailboxImportRequest', 'MailboxSearch', 'RetentionPolicy',
    'MailboxPlan', 'OrganizationRelationship', 'ADServerSettings', 'PublicFolder', 'MailPublicFolder', 'MessageTrackingLog', 'MessageTrace',
    'Queue', 'TransportConfig', 'TransportService', 'ExchangeCertificate', 'User', 'Contact', 'Group', 'Mailboxdatabase', 'OwaVirtualDirectory',
    'ClientAccessServer', 'CalendarNotification', 'MailboxCalendarConfiguration', 'ADPermission', 'RoleGroupMember', 'ManagementRoleAssignment',
    'MailboxSpellingConfiguration', 'ActiveSyncDevice', 'MobileDevice', 'MailboxArchive', 'LinkedUser', 'RemoteDomain', 'OutboundConnector', 'InboundConnector',
    'GlobalAddressList', 'OfflineAddressBook', 'AddressBookPolicy', 'AdminAuditLogConfig', 'RoleGroup', 'ManagementRole', 'ManagementScope', 'RoleAssignmentPolicy',
    'JournalRule', 'TransportAgent', 'AcceptedDomain', 'RetentionPolicyTag', 'MailboxAuditBypassAssociation', 'SharingPolicy', 'OrganizationConfig',
    'MigrationEndpoint', 'MigrationConfig', 'MailboxRestoreRequest', 'MailboxRepairRequest', 'PublicFolderMailboxMigrationRequest', 'MailboxSearch',
    'ComplianceSearch', 'DlpPolicy', 'MalwareFilterPolicy', 'HostedContentFilterPolicy', 'MobileDeviceMailboxPolicy', 'OwaMailboxPolicy', 'ClientAccessRule',
    'AuthenticationPolicy', 'CASMailboxPlan', 'ResourceConfig', 'UMMailbox', 'UMMailboxPolicy', 'MailboxFolderStatistics', 'MailboxFolder') + $script:OnPremOnlyNouns
$script:MutatingVerbs = @('Set', 'New', 'Remove', 'Enable', 'Disable', 'Add', 'Update', 'Move', 'Start', 'Stop', 'Suspend', 'Resume', 'Complete', 'Grant', 'Revoke', 'Undo', 'Clear', 'Reset', 'Restore', 'Unlock', 'Rename', 'Send')
# Exchange nouns that begin with 'AD' and must not be classified as ActiveDirectory-module cmdlets.
$script:ExchangeAdPrefixedNouns = @('ADServerSettings', 'ADPermission', 'ADSite', 'ADSiteLink')

function Get-CmdletFamily {
    param([string]$Noun)
    if ($Noun -clike 'Mg*') { return 'MicrosoftGraph' }
    if ($Noun -clike 'AzureAD*') { return 'AzureAD' }
    if ($Noun -clike 'Msol*') { return 'MSOnline' }
    if ($Noun -clike 'EXO*' -or $Noun -eq 'ExchangeOnline' -or $Noun -eq 'IPPSSession') { return 'ExchangeOnlineManagement' }
    if ($Noun -clike 'ADSync*') { return 'ADSync' }
    # Case-sensitive: the ActiveDirectory module's nouns are 'AD' + capital (ADUser, ADGroup,
    # ADComputer). A case-insensitive 'AD*' also swallowed AddressList, AdminAuditLogConfig
    # and AddressBookPolicy (finding 41).
    if ($Noun -cmatch '^AD[A-Z]' -and $script:ExchangeAdPrefixedNouns -cnotcontains $Noun) { return 'ActiveDirectory' }
    if ($Noun -clike 'Cs*' -or $Noun -clike 'Team*') { return 'Teams' }
    if ($Noun -clike 'SPO*' -or $Noun -clike 'PnP*') { return 'SharePoint' }
    if ($Noun -clike 'Mailbox*' -or $script:ExchangeNouns -contains $Noun) { return 'Exchange' }
    return $null
}

function Get-ScriptFingerprint {
    # Reads a script to identify which cmdlets it uses. Only cmdlet names and boolean flags
    # are returned. No file content, matched lines or values ever leave this function.
    param([string]$Path)
    $fp = [ordered]@{
        Path         = Protect-FilePath -Value $Path
        FileNameHint = Get-FileNameHint -Path $Path
        Extension    = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        SizeBytes    = $null
        LastModified = $null
        Sha256Prefix = $null
        LineCount    = $null
        Fingerprinted = $false
    }
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        $fp.SizeBytes    = $fi.Length
        $fp.LastModified = ConvertTo-IsoString -Value $fi.LastWriteTime
        $fp.Sha256Prefix = Get-FileSha256Prefix -Path $Path
        if ($fp.Extension -notin @('.ps1', '.psm1', '.vbs', '.bat', '.cmd')) { return $fp }
        if ($fi.Length -gt 3MB) { $fp.Note = 'Skipped: larger than 3 MB'; return $fp }
        $content = [System.IO.File]::ReadAllText($Path)
        $fp.LineCount = ([regex]::Matches($content, "`n")).Count + 1
        $fp.IsMicrosoftCopyright = ($content -match '(?i)Copyright\s*(\(c\))?\s*Microsoft')
        $found = @{}
        foreach ($m in [regex]::Matches($content, '\b(Get|Set|New|Remove|Enable|Disable|Add|Update|Start|Stop|Connect|Disconnect|Import|Export|Test|Search|Move|Suspend|Resume|Complete|Undo|Invoke|Grant|Revoke|Send|Clear|Reset|Restore|Unlock|Rename)-([A-Z][A-Za-z0-9]+)\b')) {
            $verb = $m.Groups[1].Value; $noun = $m.Groups[2].Value
            $fam = Get-CmdletFamily -Noun $noun
            if ($null -eq $fam) { continue }
            $found["$verb-$noun"] = $fam
        }
        $families = @{}
        $mutating = 0
        $onPremOnly = @()
        foreach ($k in $found.Keys) {
            $families[$found[$k]] = $true
            $verb = $k.Split('-')[0]; $noun = $k.Substring($verb.Length + 1)
            if ($script:MutatingVerbs -contains $verb) { $mutating++ }
            if ($script:OnPremOnlyNouns -contains $noun) { $onPremOnly += $k }
        }
        $fp.Fingerprinted   = $true
        $fp.CmdletCount     = $found.Count
        $fp.Cmdlets         = @($found.Keys | Sort-Object | Select-Object -First 120)
        $fp.Families        = @($families.Keys | Sort-Object)
        $fp.MutatingCmdletCount = $mutating
        $fp.OnPremOnlyExchangeCmdlets = @($onPremOnly | Sort-Object)
        $fp.Flags = [ordered]@{
            PlainTextSecureStringConversion = ($content -match '(?i)ConvertTo-SecureString[^\r\n]*-AsPlainText')
            LiteralPasswordOrSecretPattern  = ($content -match '(?i)(\bpassword\s*=\s*[''"][^''"]{3,}[''"])|(-Password\s+[''"][^''"]{3,}[''"])|(\bClientSecret\s*=\s*[''"][^''"]{6,}[''"])|(-ClientSecret\s+[''"][^''"]{6,}[''"])|(\bsecret\s*=\s*[''"][^''"]{8,}[''"])')
            UsesGetCredentialPrompt         = ($content -match '(?i)\bGet-Credential\b')
            UsesImportClixmlCredential      = ($content -match '(?i)\bImport-Clixml\b')
            UsesCertificateAuth             = ($content -match '(?i)-CertificateThumbprint|-CertificateFilePath|-Certificate\s')
            UsesAppIdOrClientId             = ($content -match '(?i)-AppId\s|-ApplicationId\s|-ClientId\s|ClientId\s*=')
            UsesConnectExchangeOnline       = ($content -match '(?i)\bConnect-ExchangeOnline\b')
            UsesBasicAuthRemoting           = ($content -match '(?i)-Authentication\s+Basic|ps\.outlook\.com|outlook\.office365\.com/powershell')
            UsesOnPremExchangeRemoting      = ($content -match '(?i)-ConfigurationName\s+Microsoft\.Exchange|/PowerShell/?[''"\s]|RemoteExchange\.ps1|Microsoft\.Exchange\.Management\.PowerShell')
            UsesStartADSyncSyncCycle        = ($content -match '(?i)\bStart-ADSyncSyncCycle\b')
            UsesMsolOrAzureAdModule         = ($content -match '(?i)\bConnect-MsolService\b|\bConnect-AzureAD\b')
            UsesGraph                       = ($content -match '(?i)\bConnect-MgGraph\b|graph\.microsoft\.com')
            CallsOtherScripts               = ($content -match '(?i)\.ps1[''"\s]')
            ReadsCsvInput                   = ($content -match '(?i)\bImport-Csv\b')
            SendsEmail                      = ($content -match '(?i)\bSend-MailMessage\b|\bSend-MgUserMail\b|System\.Net\.Mail\.SmtpClient')
            ReferencesSmtpServerParameter   = ($content -match '(?i)-SmtpServer\s')
            ReferencesLocalHostnameAsSmtp   = [bool]($env:COMPUTERNAME -and ($content -match ('(?i)-SmtpServer\s+[''"]?' + [regex]::Escape($env:COMPUTERNAME))))
            ReferencesLicensingCmdlets      = ($content -match '(?i)Set-MsolUserLicense|Set-MgUserLicense|AssignedLicenses|Set-AzureADUserLicense')
            ReferencesEnableDisableMailbox  = ($content -match '(?i)\b(Enable|Disable|New)-(Remote)?Mailbox\b')
        }
    }
    catch { $fp.Error = ConvertTo-SafeError -ErrorRecord $_ }
    return $fp
}

function Get-ScriptPathsFromCommandLine {
    param([string]$Path, [string]$Arguments, [string]$WorkingDirectory)
    $paths = @()
    $text = "$Path $Arguments"
    foreach ($m in [regex]::Matches($text, '(?i)("[^"]+\.(ps1|psm1|vbs|bat|cmd)"|''[^'']+\.(ps1|psm1|vbs|bat|cmd)''|[^\s"'']+\.(ps1|psm1|vbs|bat|cmd))')) {
        $p = $m.Value.Trim('"', "'")
        if (-not [System.IO.Path]::IsPathRooted($p) -and $WorkingDirectory) { try { $p = Join-Path $WorkingDirectory $p } catch { } }
        $paths += $p
    }
    return ,$paths
}

function Test-ScanRootAllowed {
    # Finding 23: only absolute local folders are walked. Drive roots ('C:\'), drive-relative
    # paths ('c:'), UNC paths (a dead server blocks Test-Path for 45-90 s) and anything under
    # %WINDIR%, %ProgramFiles% or %ProgramFiles(x86)% are rejected as scan roots.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.Trim().Trim('"').Trim("'").TrimEnd('\', '/')
    if ($p -match '^\\\\') { return $false }
    if ($p -match '^[A-Za-z]:$') { return $false }
    if ($p -notmatch '^[A-Za-z]:\\[^\\].*') { return $false }
    $lower = $p.ToLowerInvariant()
    foreach ($envName in @('windir', 'SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if ($v) { $vl = $v.TrimEnd('\').ToLowerInvariant(); if ($lower -eq $vl -or $lower.StartsWith($vl + '\')) { return $false } }
    }
    if ($lower -match '\\(\$recycle\.bin|system volume information|winsxs|windows|program files|program files \(x86\))(\\|$)') { return $false }
    return $true
}

function Get-ScriptFilesUnderRoot {
    # Bounded, depth-limited walk without -Recurse: the depth cap is enforced DURING traversal,
    # reparse points (junctions, symlinks) are never followed, and the walk stops at the file
    # cap, the directory cap or the global deadline. Returns paths plus truncation flags.
    param([string]$Root, [int]$MaxDepth = 3, [int]$MaxFiles = 300, [int]$MaxDirs = 1500)
    $exts = @('.ps1', '.psm1', '.vbs', '.bat', '.cmd')
    $skipLeaves = @('node_modules', '.git', '$recycle.bin', 'system volume information', 'windows', 'program files', 'program files (x86)', 'winsxs', 'appdata')
    $files = New-Object System.Collections.Generic.List[string]
    $dirsVisited = 0; $depthLimitHit = $false; $fileCapHit = $false; $dirCapHit = $false; $deadline = $false
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@{ Path = $Root; Depth = 0 })
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $dirsVisited++
        if ($dirsVisited -gt $MaxDirs) { $dirCapHit = $true; break }
        if (($dirsVisited % 50) -eq 0 -and (Test-PastDeadline)) { $deadline = $true; break }
        try {
            foreach ($f in [System.IO.Directory]::GetFiles($cur.Path)) {
                if ($exts -contains ([System.IO.Path]::GetExtension($f).ToLowerInvariant())) {
                    $files.Add($f)
                    if ($files.Count -ge $MaxFiles) { $fileCapHit = $true; break }
                }
            }
        }
        catch { }
        if ($fileCapHit) { break }
        $subDirs = @()
        try { $subDirs = @([System.IO.Directory]::GetDirectories($cur.Path)) } catch { $subDirs = @() }
        if ($cur.Depth -ge $MaxDepth) { if ($subDirs.Count -gt 0) { $depthLimitHit = $true }; continue }
        foreach ($d in $subDirs) {
            $leaf = [System.IO.Path]::GetFileName($d).ToLowerInvariant()
            if ($skipLeaves -contains $leaf) { continue }
            try { $attr = [System.IO.File]::GetAttributes($d); if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
            $stack.Push(@{ Path = $d; Depth = ($cur.Depth + 1) })
        }
    }
    return ([ordered]@{ Files = @($files.ToArray()); DirectoriesVisited = $dirsVisited; DepthLimitHit = $depthLimitHit; FileCapHit = $fileCapHit; DirectoryCapHit = $dirCapHit; StoppedAtDeadline = $deadline })
}

function Get-AutomationSection {
    $out = [ordered]@{}
    $scriptCandidates = New-Object System.Collections.Generic.List[string]
    $dirCandidates    = New-Object System.Collections.Generic.List[string]
    $script:Ctx.ScheduledTaskTotalSeen = 0
    $script:Ctx.ScheduledTasksTruncated = $false
    $script:Ctx.ScheduledTasksUnreadable = 0

    # --- Scheduled tasks (Task Scheduler COM; works on every supported OS) ---------------
    # Emitted per task: hashed name/path, folder depth, whitelisted purpose keywords from the
    # name and description, state, timing, run-as (hashed), and DERIVED action facts only
    # (executable leaf, argument length and pattern flags, protected script paths). The raw
    # argument string, task name, path and description are never written (findings 2, 3, 16).
    $out.ScheduledTasks = Invoke-Guarded -What 'Scheduled tasks' -Script {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $tasks = New-Object System.Collections.ArrayList
        $folders = New-Object System.Collections.Queue
        $folders.Enqueue($svc.GetFolder('\'))
        $stateNames = @{ 0 = 'Unknown'; 1 = 'Disabled'; 2 = 'Queued'; 3 = 'Ready'; 4 = 'Running' }
        $triggerNames = @{ 0 = 'Event'; 1 = 'Time'; 2 = 'Daily'; 3 = 'Weekly'; 4 = 'Monthly'; 5 = 'MonthlyDOW'; 6 = 'Idle'; 7 = 'Registration'; 8 = 'Boot'; 9 = 'Logon'; 11 = 'SessionStateChange'; 12 = 'Custom' }
        $scriptHosts = @('powershell.exe', 'pwsh.exe', 'cscript.exe', 'wscript.exe', 'cmd.exe')
        $totalSeen = 0; $unreadable = 0; $truncated = $false; $taskCap = 300
        while ($folders.Count -gt 0 -and -not $truncated) {
            $folder = $folders.Dequeue()
            try { foreach ($sub in $folder.GetFolders(0)) { $folders.Enqueue($sub) } } catch { }
            $taskList = $null
            try { $taskList = $folder.GetTasks(1) } catch { continue }
            foreach ($t in $taskList) {
                $totalSeen++
                if (($totalSeen % 50) -eq 0) { Assert-Deadline }
                # Every COM property read is inside this try (finding 30): one corrupt task
                # registration must not discard the tasks collected so far.
                try {
                    $path = "$($t.Path)"
                    $name = "$($t.Name)"
                    $isMicrosoftFolder = ($path -like '\Microsoft\*')
                    $actions = @()
                    $referencesScript = $false
                    try {
                        foreach ($a in $t.Definition.Actions) {
                            if ($a.Type -eq 0) {
                                $exe = "$($a.Path)"; $argText = "$($a.Arguments)"; $wd = "$($a.WorkingDirectory)"
                                $sps = @(Get-ScriptPathsFromCommandLine -Path $exe -Arguments $argText -WorkingDirectory $wd)
                                foreach ($sp in $sps) { [void]$scriptCandidates.Add($sp) }
                                if ($sps.Count -gt 0) { $referencesScript = $true }
                                if ($wd) { [void]$dirCandidates.Add($wd) }
                                $exeLeaf = ''; try { $exeLeaf = [System.IO.Path]::GetFileName($exe.Trim('"', "'")).ToLowerInvariant() } catch { $exeLeaf = '' }
                                $actions += [ordered]@{
                                    Type                   = 'Exec'
                                    Executable             = $(if ($script:GenericExecutables -contains $exeLeaf) { $exeLeaf } else { Protect-FilePath -Value $exe })
                                    ExecutableIsScriptHost = ($scriptHosts -contains $exeLeaf)
                                    ArgumentLength         = $argText.Length
                                    ArgumentHasPasswordPattern    = [bool]($argText -match '(?i)(^|[\s"''])(-|--|/)(password|pass|pwd|p|secret|clientsecret|token|apikey|key|credential)\b|(password|passwd|pwd|secret)\s*[:=]')
                                    ArgumentHasEncodedCommand     = [bool]($argText -match '(?i)-e(nc|ncoded|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}')
                                    ArgumentHasInlineCommand      = [bool]($argText -match '(?i)(^|\s)-c(ommand)?\s')
                                    ArgumentExecutionPolicyBypass = [bool]($argText -match '(?i)-ex(ecutionpolicy)?\s+(bypass|unrestricted)')
                                    ArgumentReferencesUncPath     = [bool]($argText -match '\\\\[^\\\s]+\\')
                                    ReferencesScript       = ($sps.Count -gt 0)
                                    ScriptPaths            = @(foreach ($sp in $sps) { Protect-FilePath -Value $sp })
                                    ScriptFileNameHints    = @(foreach ($sp in $sps) { Get-FileNameHint -Path $sp })
                                    WorkingDirectory       = Protect-FilePath -Value $wd
                                }
                            }
                            elseif ($a.Type -eq 5) { $actions += [ordered]@{ Type = 'ComHandler'; ClassId = "$($a.ClassId)" } }
                            elseif ($a.Type -eq 6) { $actions += [ordered]@{ Type = 'SendEmail' } }
                            elseif ($a.Type -eq 7) { $actions += [ordered]@{ Type = 'ShowMessage' } }
                        }
                    }
                    catch { $actions += [ordered]@{ Type = 'unreadable' } }
                    if ($isMicrosoftFolder -and -not $referencesScript) { continue }
                    $triggers = @()
                    try {
                        foreach ($tr in $t.Definition.Triggers) {
                            $trName = $(if ($triggerNames.ContainsKey([int]$tr.Type)) { $triggerNames[[int]$tr.Type] } else { "Type$($tr.Type)" })
                            $rep = $null; try { $rep = "$($tr.Repetition.Interval)" } catch { }
                            $triggers += [ordered]@{ Type = $trName; Enabled = $tr.Enabled; StartBoundary = "$($tr.StartBoundary)"; RepetitionInterval = $rep }
                        }
                    }
                    catch { }
                    $lastRun = $null; try { $lastRun = ConvertTo-IsoString -Value $t.LastRunTime } catch { }
                    $nextRun = $null; try { $nextRun = ConvertTo-IsoString -Value $t.NextRunTime } catch { }
                    $author = $null; try { $author = Protect-Account -Value "$($t.Definition.RegistrationInfo.Author)" } catch { }
                    $desc = ''; try { $desc = "$($t.Definition.RegistrationInfo.Description)" } catch { $desc = '' }
                    $runAs = $null; $logonType = $null; $runLevel = $null
                    try { $runAs = Protect-Account -Value "$($t.Definition.Principal.UserId)"; $logonType = $t.Definition.Principal.LogonType; $runLevel = $t.Definition.Principal.RunLevel } catch { }
                    $enabled = $null; try { $enabled = [bool]$t.Enabled } catch { }
                    $state = $null; try { $state = $(if ($stateNames.ContainsKey([int]$t.State)) { $stateNames[[int]$t.State] } else { "$($t.State)" }) } catch { }
                    $lastResult = $null; $lastResultHex = $null
                    try { $lastResult = $t.LastTaskResult; $lastResultHex = ('0x{0:X8}' -f ([int64]$lastResult -band 0xFFFFFFFF)) } catch { }
                    [void]$tasks.Add([ordered]@{
                        NameId            = Protect-Identifier -Value $name
                        NameHint          = Get-FileNameHint -Path $name
                        NameKeywords      = Get-PurposeKeywords -Text $name
                        PathId            = Protect-Identifier -Value $path
                        FolderDepth       = [math]::Max(0, ($path.Split('\').Count - 2))
                        InMicrosoftFolder = $isMicrosoftFolder
                        DescriptionPresent  = ($desc.Length -gt 0)
                        DescriptionLength   = $desc.Length
                        DescriptionKeywords = Get-PurposeKeywords -Text $desc
                        Enabled           = $enabled
                        State             = $state
                        LastRunTime       = $lastRun
                        LastTaskResult    = $lastResult
                        LastTaskResultHex = $lastResultHex
                        NextRunTime       = $nextRun
                        Author            = $author
                        RunAs             = $runAs
                        LogonType         = $logonType
                        RunLevel          = $runLevel
                        Triggers          = $triggers
                        Actions           = $actions
                        ReferencesScript  = $referencesScript
                    })
                    if ($tasks.Count -ge $taskCap) { $truncated = $true; break }
                }
                catch { $unreadable++ }
            }
        }
        $script:Ctx.ScheduledTaskTotalSeen = $totalSeen
        $script:Ctx.ScheduledTasksTruncated = $truncated
        $script:Ctx.ScheduledTasksUnreadable = $unreadable
        ,@($tasks.ToArray())
    }
    $out.ScheduledTaskCountNonMicrosoft = Get-SafeCount -Value $out.ScheduledTasks
    $out.ScheduledTaskTotalSeen = $script:Ctx.ScheduledTaskTotalSeen
    $out.ScheduledTasksTruncatedAtCap = [bool]$script:Ctx.ScheduledTasksTruncated
    $out.ScheduledTasksUnreadable = [int]$script:Ctx.ScheduledTasksUnreadable
    $out.ScheduledTaskNote = 'Tasks under \Microsoft\ are omitted unless they run a script. Names, paths, descriptions and arguments are reduced to hashes, lengths and whitelisted keywords. Run elevated to see tasks registered by other accounts.'

    # --- Script discovery ----------------------------------------------------------------
    $out.Scripts = Invoke-Guarded -What 'Script discovery' -Script {
        $roots = New-Object System.Collections.Generic.List[string]
        $rejectedRoots = 0; $uncScriptRefs = 0
        foreach ($r in @('C:\Scripts', 'C:\Script', 'C:\Automation', 'C:\Tasks', 'C:\Jobs', 'C:\Tools', 'C:\Admin', 'C:\PS', 'C:\PowerShell', 'C:\Batch', 'C:\Util', 'C:\Utils', 'D:\Scripts', 'E:\Scripts', 'C:\ProgramData\Scripts', (Join-Path $env:SystemDrive 'Scripts'))) {
            if ($r -and (Test-Path -LiteralPath $r)) { $rl = $r.TrimEnd('\').ToLowerInvariant(); if (-not $roots.Contains($rl)) { [void]$roots.Add($rl) } }
        }
        # The Exchange Scripts folder is under Program Files, so it is added explicitly (depth 1,
        # Microsoft-shipped scripts are summarised, not fingerprinted).
        $exScriptsRoot = $null
        if ($script:Ctx.ExchangeInstallPath) {
            $exScriptsRoot = (Join-Path $script:Ctx.ExchangeInstallPath 'Scripts').TrimEnd('\').ToLowerInvariant()
            if ((Test-Path -LiteralPath $exScriptsRoot) -and -not $roots.Contains($exScriptsRoot)) { [void]$roots.Add($exScriptsRoot) }
        }
        # Roots harvested from scheduled tasks are validated (finding 23) before any Test-Path.
        $candidateDirs = @()
        foreach ($d in $dirCandidates) { $candidateDirs += "$d" }
        foreach ($s in $scriptCandidates) { try { $d = [System.IO.Path]::GetDirectoryName($s); if ($d) { $candidateDirs += $d } } catch { } }
        foreach ($d in $candidateDirs) {
            if (-not (Test-ScanRootAllowed -Path $d)) { $rejectedRoots++; continue }
            $dl = $d.Trim().Trim('"', "'").TrimEnd('\').ToLowerInvariant()
            if ($roots.Contains($dl)) { continue }
            if (Test-Path -LiteralPath $dl) { [void]$roots.Add($dl) }
        }
        $rootCap = 25; $rootsTruncated = ($roots.Count -gt $rootCap)

        $files = @{}
        foreach ($s in $scriptCandidates) {
            if (-not $s) { continue }
            if ($s -match '^\\\\') { $uncScriptRefs++; continue }                 # never touch UNC
            if ($s -notmatch '^[A-Za-z]:\\') { continue }                          # drive-relative / relative
            if (Test-Path -LiteralPath $s) { $files[$s.ToLowerInvariant()] = @{ Path = $s; FromTask = $true; ExchangeScriptsFolder = $false } }
        }
        $perRootCap = 300; $maxDepth = 3
        $rootSummaries = @(); $n = 0; $anyDepthHit = $false; $anyFileCapHit = $false; $walkDeadline = $false
        foreach ($root in $roots) {
            $n++
            if ($n -gt $rootCap) { break }
            if (Test-PastDeadline) { $walkDeadline = $true; break }
            $isExRoot = ($root -eq $exScriptsRoot)
            $walk = Get-ScriptFilesUnderRoot -Root $root -MaxDepth $(if ($isExRoot) { 1 } else { $maxDepth }) -MaxFiles $perRootCap
            foreach ($f in $walk.Files) {
                $key = $f.ToLowerInvariant()
                if (-not $files.ContainsKey($key)) { $files[$key] = @{ Path = $f; FromTask = $false; ExchangeScriptsFolder = $isExRoot } }
            }
            if ($walk.DepthLimitHit) { $anyDepthHit = $true }
            if ($walk.FileCapHit) { $anyFileCapHit = $true }
            if ($walk.StoppedAtDeadline) { $walkDeadline = $true }
            $rootSummaries += [ordered]@{ Root = (Protect-FilePath -Value $root); FilesFound = $walk.Files.Count; DirectoriesVisited = $walk.DirectoriesVisited; DepthLimitHit = $walk.DepthLimitHit; FileCapHit = $walk.FileCapHit; DirectoryCapHit = $walk.DirectoryCapHit; IsExchangeScriptsFolder = $isExRoot }
        }
        # Fingerprint task-referenced scripts first so the cap never drops them.
        $results = @()
        $fingerprintCap = 400
        $i = 0; $fpTruncated = $false; $fpDeadline = $false
        $orderedKeys = @($files.Keys | Sort-Object -Property @{ Expression = { -not $files[$_].FromTask } }, @{ Expression = { $_ } })
        foreach ($key in $orderedKeys) {
            $entry = $files[$key]
            $i++
            if ($i -gt $fingerprintCap) { $fpTruncated = $true; break }
            if (($i % 25) -eq 0 -and (Test-PastDeadline)) { $fpDeadline = $true; break }
            $fp = Get-ScriptFingerprint -Path $entry.Path
            $fp['ReferencedByScheduledTask'] = [bool]$entry.FromTask
            $fp['InExchangeScriptsFolder']   = [bool]$entry.ExchangeScriptsFolder
            if ($fp['InExchangeScriptsFolder'] -and $fp['IsMicrosoftCopyright'] -eq $true) {
                # Microsoft's own scripts: keep only the summary line, not the cmdlet fingerprint.
                $results += [ordered]@{ Path = $fp.Path; MicrosoftShippedScript = $true; SizeBytes = $fp.SizeBytes; LastModified = $fp.LastModified }
                continue
            }
            $results += $fp
        }
        [ordered]@{
            RootsScanned              = $rootSummaries
            RootsRejected             = $rejectedRoots
            RootsTruncatedAtCap       = $rootsTruncated
            UncScriptReferencesSkipped = $uncScriptRefs
            CandidateFileCount        = $files.Count
            FingerprintedCount        = @($results | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['Fingerprinted'] -eq $true }).Count
            FingerprintTruncatedAtCap = $fpTruncated
            DepthLimitHitInAnyRoot    = $anyDepthHit
            FileCapHitInAnyRoot       = $anyFileCapHit
            StoppedAtDeadline         = ($walkDeadline -or $fpDeadline)
            Files                     = $results
        }
    }
    $customScripts = @()
    try { $customScripts = @($out.Scripts.Files | Where-Object { $_ -is [System.Collections.IDictionary] -and -not $_['MicrosoftShippedScript'] }) } catch { }
    $out.AutomationScriptCount = $customScripts.Count
    $out.ScriptsUsingExchangeCmdlets = @($customScripts | Where-Object { $_['Families'] -contains 'Exchange' }).Count
    $out.ScriptsUsingOnPremOnlyCmdlets = @($customScripts | Where-Object { (Get-SafeCount -Value $_['OnPremOnlyExchangeCmdlets']) -gt 0 }).Count
    $out.ScriptsUsingCloudModules = @($customScripts | Where-Object { $_['Families'] -contains 'ExchangeOnlineManagement' -or $_['Families'] -contains 'MicrosoftGraph' -or $_['Families'] -contains 'AzureAD' -or $_['Families'] -contains 'MSOnline' }).Count
    $out.ScriptsWithCredentialPatterns = @($customScripts | Where-Object { $_['Flags'] -is [System.Collections.IDictionary] -and ($_['Flags']['PlainTextSecureStringConversion'] -or $_['Flags']['LiteralPasswordOrSecretPattern']) }).Count
    # Finding 13: DPAPI-protected credentials (Import-Clixml / ConvertTo-SecureString from file)
    # are bound to the machine and account that created them and cannot move to a new server.
    $out.ScriptsUsingImportClixmlCredential = @($customScripts | Where-Object { $_['Flags'] -is [System.Collections.IDictionary] -and $_['Flags']['UsesImportClixmlCredential'] -eq $true }).Count
    $out.ScriptsReferencedByScheduledTasks = @($customScripts | Where-Object { $_['ReferencedByScheduledTask'] -eq $true }).Count
    $out.TruncationFlags = [ordered]@{
        ScheduledTasksTruncatedAtCap = [bool]$script:Ctx.ScheduledTasksTruncated
        ScriptRootsTruncatedAtCap    = $(try { [bool]$out.Scripts.RootsTruncatedAtCap } catch { $null })
        ScriptDepthLimitHit          = $(try { [bool]$out.Scripts.DepthLimitHitInAnyRoot } catch { $null })
        ScriptFileCapHit             = $(try { [bool]$out.Scripts.FileCapHitInAnyRoot } catch { $null })
        FingerprintTruncatedAtCap    = $(try { [bool]$out.Scripts.FingerprintTruncatedAtCap } catch { $null })
        StoppedAtDeadline            = $(try { [bool]$out.Scripts.StoppedAtDeadline } catch { $null })
    }
    $script:Ctx.AutomationScriptCount = $out.AutomationScriptCount
    $script:Ctx.ScheduledTaskCount = $out.ScheduledTaskCountNonMicrosoft
    $script:Ctx.ScriptsUsingImportClixmlCredential = $out.ScriptsUsingImportClixmlCredential
    $script:Ctx.AutomationTruncated = [bool](($out.TruncationFlags.Values | Where-Object { $_ -eq $true }).Count -gt 0)

    # --- PowerShell modules relevant to identity / mail automation -----------------------
    $out.RelevantModules = Invoke-Guarded -What 'Modules' -Script {
        $names = @('ExchangeOnlineManagement', 'MSOnline', 'AzureAD', 'AzureADPreview', 'Microsoft.Graph', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'ActiveDirectory', 'ADSync', 'MicrosoftTeams', 'Microsoft.Online.SharePoint.PowerShell', 'PnP.PowerShell', 'Az.Accounts', 'AzureRM', 'PSWindowsUpdate', 'ImportExcel', 'Microsoft.Exchange.Management.ExoPowershellModule')
        @(Get-Module -ListAvailable -Name $names -ErrorAction SilentlyContinue | Sort-Object Name, Version -Descending | ForEach-Object {
            [ordered]@{ Name = $_.Name; Version = "$($_.Version)"; Path = (Protect-FilePath -Value $_.ModuleBase) }
        } | Select-Object -First 60)
    }
    $out.RegisteredSnapins = Invoke-Guarded -What 'Snap-ins' -Script { @(Get-PSSnapin -Registered -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) $($_.Version)" }) }

    # --- Services running as domain / custom accounts ------------------------------------
    $out.ServicesWithCustomAccounts = Invoke-Guarded -What 'Service accounts' -Script {
        @(Get-CimSafe -Class 'Win32_Service' | Where-Object {
            $sn = "$($_.StartName)"
            $sn -and $sn -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|LocalService|NetworkService|NT Service\\)'
        } | ForEach-Object {
            [ordered]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode; RunAs = (Protect-Account -Value "$($_.StartName)"); IsDomainAccount = ("$($_.StartName)" -notlike ".\*" -and "$($_.StartName)" -notlike "$env:COMPUTERNAME\*"); ExePath = (Protect-FilePath -Value "$($_.PathName)") }
        } | Select-Object -First 100)
    }

    # --- Automation / ITSM / RMM runners -------------------------------------------------
    $out.AutomationRunners = Invoke-Guarded -What 'Automation runners' -Script {
        $pattern = 'Jenkins|Octopus|Azure Automation|Hybrid Runbook|HybridWorker|Ansible|Puppet|Chef|Salt|ConnectWise|Automate|N-able|N-central|Ninja|Kaseya|Datto|ServiceNow|Jira|Freshservice|ManageEngine|ADManager|Adaxes|Cayosoft|Netwrix|PowerShell Universal|Universal Automation|Zapier|Power Automate|Rundeck|AutoMate|Tidal|Control-M|Identity Manager|SailPoint|Saviynt|Omada|Okta|JumpCloud|OneLogin|Intune|Atera|Syncro|Pulseway|Action1|Task Scheduler Managed|VisualCron|JAMS|ActiveBatch|Scheduler|Orchestrator|Runbook'
        $hits = @()
        foreach ($s in @(Get-CimSafe -Class 'Win32_Service' | Where-Object { "$($_.DisplayName)" -match $pattern -or "$($_.Name)" -match $pattern })) { $hits += [ordered]@{ Source = 'Service'; Name = $s.DisplayName; State = $s.State } }
        foreach ($p in @(Get-InstalledProgramList | Where-Object { "$($_.DisplayName)" -match $pattern })) { $hits += [ordered]@{ Source = 'InstalledProgram'; Name = $p.DisplayName; Version = $p.DisplayVersion } }
        ,@($hits | Select-Object -First 50)
    }

    return $out
}

# =======================================================================================
# SECTION J - Network / Azure readiness
# =======================================================================================
function Test-TcpPort {
    # Plain TCP connect with a short timeout. No data is sent; the socket is closed at once.
    param([string]$TargetHost, [int]$Port, [int]$TimeoutMs = 3000)
    $client = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $client.Connected) { $client.EndConnect($ar); $sw.Stop(); return ([ordered]@{ Result = 'Open'; Ms = [int]$sw.ElapsedMilliseconds }) }
        $sw.Stop()
        return ([ordered]@{ Result = 'TimeoutOrRefused'; Ms = [int]$sw.ElapsedMilliseconds })
    }
    catch { $sw.Stop(); return ([ordered]@{ Result = 'Error'; Ms = [int]$sw.ElapsedMilliseconds; Error = (ConvertTo-SafeError -ErrorRecord $_) }) }
    finally { if ($null -ne $client) { try { $client.Close() } catch { } } }
}

function Get-NetworkSection {
    $out = [ordered]@{}

    $out.IpConfiguration = Invoke-Guarded -What 'IP configuration' -Script {
        $cfg = @()
        if (Test-CmdletAvailable -Name 'Get-NetIPConfiguration') {
            foreach ($i in @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4Address })) {
                $gw = $null; try { $gw = @($i.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) } catch { }
                $cfg += [ordered]@{
                    Interface    = $i.InterfaceAlias
                    Description  = $i.InterfaceDescription
                    IPv4Address  = @($i.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
                    Gateway      = $gw
                    DnsServers   = @($i.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | ForEach-Object { $_ })
                    NetProfile   = "$(Get-PropertySafe -InputObject $i -Name 'NetProfile')"
                }
            }
        }
        else {
            foreach ($n in @(Get-CimSafe -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE')) {
                $cfg += [ordered]@{ Interface = $n.Description; IPv4Address = @($n.IPAddress); SubnetMask = @($n.IPSubnet); Gateway = @($n.DefaultIPGateway); DnsServers = @($n.DNSServerSearchOrder); DhcpEnabled = $n.DHCPEnabled }
            }
        }
        ,$cfg
    }

    $out.PrivateRoutes = Invoke-Guarded -What 'Routes' -Script {
        if (-not (Test-CmdletAvailable -Name 'Get-NetRoute')) { return 'Get-NetRoute not available' }
        @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0/0)' -and $_.DestinationPrefix -notmatch '/32$' } | Sort-Object DestinationPrefix | Select-Object -First 60 | ForEach-Object {
            [ordered]@{ Destination = $_.DestinationPrefix; NextHop = $_.NextHop; Interface = $_.InterfaceAlias; Metric = $_.RouteMetric }
        })
    }

    $out.Mtu = Invoke-Guarded -What 'MTU' -Script {
        if (-not (Test-CmdletAvailable -Name 'Get-NetIPInterface')) { return 'Get-NetIPInterface not available' }
        @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -notmatch 'Loopback' } | ForEach-Object { [ordered]@{ Interface = $_.InterfaceAlias; NlMtu = $_.NlMtu; Dhcp = "$($_.Dhcp)" } })
    }

    $out.VpnAndRouting = Invoke-Guarded -What 'VPN / RRAS' -Script {
        $v = [ordered]@{}
        $rras = @(Get-CimSafe -Class 'Win32_Service' -Filter "Name='RemoteAccess' OR Name='RasMan' OR Name='IKEEXT'")
        $v.Services = @(foreach ($s in $rras) { [ordered]@{ Name = $s.Name; State = $s.State; StartMode = $s.StartMode } })
        if (Test-CmdletAvailable -Name 'Get-VpnConnection') { $v.ClientVpnConnections = @(Get-VpnConnection -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ Name = (Protect-Hostname -Value "$($_.Name)"); Server = (Protect-Hostname -Value "$($_.ServerAddress)"); TunnelType = "$($_.TunnelType)"; Status = "$($_.ConnectionStatus)" } }) }
        $v.ThirdPartyVpnClients = @(Get-InstalledProgramList | Where-Object { "$($_.DisplayName)" -match 'AnyConnect|GlobalProtect|FortiClient|NetExtender|WireGuard|OpenVPN|Azure VPN|Pulse Secure|Ivanti Secure|Check Point|SonicWall|Zscaler|Tailscale|Cloudflare WARP|Meraki|ZeroTier' } | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" })
        $v
    }

    # Machine-wide proxy only (WinHTTP and process environment). The operator's own HKCU browser
    # proxy is personal configuration and is not read.
    $out.Proxy = Invoke-Guarded -What 'Proxy' -Script {
        $p = [ordered]@{}
        try { $p.WinHttp = @(& netsh.exe winhttp show proxy 2>$null | Where-Object { $_ -match '\S' } | ForEach-Object { Protect-Text -Text $_.Trim() }) } catch { }
        $p.EnvHttpsProxy    = $(if ($env:HTTPS_PROXY) { Protect-Hostname -Value $env:HTTPS_PROXY } else { $null })
        $p
    }

    $out.Firewall = Invoke-Guarded -What 'Firewall' -Script {
        if (-not (Test-CmdletAvailable -Name 'Get-NetFirewallProfile')) { return 'Get-NetFirewallProfile not available' }
        @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ Profile = $_.Name; Enabled = [bool]$_.Enabled; DefaultInbound = "$($_.DefaultInboundAction)"; DefaultOutbound = "$($_.DefaultOutboundAction)" } })
    }

    if ($script:SkipNet) {
        $out.ConnectivityTests = 'Skipped (-SkipNetworkTests)'
        return $out
    }

    # --- Connectivity tests: short TCP connects, no data, no sign-in --------------------
    $out.ConnectivityTests = Invoke-Guarded -What 'Connectivity tests' -Script {
        $tests = @()
        $dc = $script:Ctx.DcHostname
        if (-not $dc -and $env:LOGONSERVER) { $dc = $env:LOGONSERVER.TrimStart('\') }
        if ($dc) {
            foreach ($port in @(53, 88, 135, 389, 445, 636, 3268, 3269, 5985)) {
                $r = Test-TcpPort -TargetHost $dc -Port $port -TimeoutMs 2500
                $tests += [ordered]@{ Target = 'DomainController'; Host = (Protect-Hostname -Value $dc); Port = $port; Result = $r.Result; Ms = $r.Ms }
            }
        }
        $endpoints = @(
            @{ Host = 'login.microsoftonline.com'; Port = 443 },
            @{ Host = 'graph.microsoft.com';       Port = 443 },
            @{ Host = 'outlook.office365.com';     Port = 443 },
            @{ Host = 'outlook.office365.com';     Port = 25 },
            @{ Host = 'smtp.office365.com';        Port = 587 },
            @{ Host = 'management.azure.com';      Port = 443 },
            @{ Host = 'www.microsoft.com';         Port = 80 }
        )
        foreach ($e in $endpoints) {
            $resolved = $null
            try { $resolved = (@([System.Net.Dns]::GetHostAddresses($e.Host)).Count -gt 0) } catch { $resolved = $false }
            $r = $null
            if ($resolved) { $r = Test-TcpPort -TargetHost $e.Host -Port $e.Port -TimeoutMs 4000 } else { $r = [ordered]@{ Result = 'DnsResolutionFailed'; Ms = 0 } }
            $tests += [ordered]@{ Target = 'Microsoft'; Host = $e.Host; Port = $e.Port; DnsResolved = $resolved; Result = $r.Result; Ms = $r.Ms }
        }
        ,$tests
    }

    $out.LatencyToDc = Invoke-Guarded -What 'Latency to DC' -Script {
        $dc = $script:Ctx.DcHostname
        if (-not $dc) { return 'No domain controller identified' }
        $ping = New-Object System.Net.NetworkInformation.Ping
        $rtts = @(); $lost = 0
        for ($i = 0; $i -lt 4; $i++) {
            try { $reply = $ping.Send($dc, 1500); if ($reply.Status -eq 'Success') { $rtts += [int]$reply.RoundtripTime } else { $lost++ } } catch { $lost++ }
        }
        $avg = $null; if ($rtts.Count -gt 0) { $avg = [math]::Round((($rtts | Measure-Object -Average).Average), 1) }
        [ordered]@{ Host = (Protect-Hostname -Value $dc); Sent = 4; Lost = $lost; AverageRttMs = $avg; MaxRttMs = $(if ($rtts.Count -gt 0) { ($rtts | Measure-Object -Maximum).Maximum } else { $null }) }
    }

    return $out
}

# =======================================================================================
# SUMMARY - feasibility read derived from the collected sections
# =======================================================================================
function Get-SummarySection {
    $s = [ordered]@{}
    $blockers = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]
    $d = $script:Sections

    $s.ExchangeProduct       = $script:Ctx.ExchangeProduct
    $s.ExchangeVersionString = $script:Ctx.ExchangeVersionString
    $s.ExchangeInstalledLocally = $script:Ctx.ExchangeInstalled
    $s.ManagementToolsOnlyInstall = $script:Ctx.ManagementToolsOnly
    $s.ExchangeCmdletsLoaded = $script:Ctx.ExchangeToolsLoaded
    $s.ExchangeCmdletLoadMethod = $script:Ctx.ExchangeToolsMethod
    $s.ExchangeToolsMode     = $script:Ctx.ExchangeToolsMode
    # Finding 33: the measured answer and the version-inferred guess are separate fields.
    $s.ManagementInterfaceObserved  = $(if ($script:Ctx.ManagementInterfaceObserved) { $script:Ctx.ManagementInterfaceObserved } else { 'No evidence collected (section C2 did not run)' })
    $s.ManagementInterfaceByVersion = $(if ($script:Ctx.ManagementToolsOnly) { 'Management-tools-only install: Exchange Management Shell / recipient cmdlets only (no EAC, no ECP on this host)' } elseif ($script:Ctx.ExchangeVersionKey -eq 'v14') { 'Inferred from version: Exchange Management Console (MMC) + Exchange Management Shell (2010)' } elseif ($script:Ctx.ExchangeVersionKey -eq 'v15') { 'Inferred from version: Exchange Admin Center (web) + Exchange Management Shell' } elseif ($script:Ctx.OrgMaxFamily) { 'Inferred from AD (no local install): ' + $script:Ctx.OrgMaxFamily } else { 'Unknown' })
    $s.OrganizationName      = $(try { $d['ExchangeDetection'].ActiveDirectory.OrganizationName } catch { $null })
    $s.ExchangeServerCountInOrg = $(try { $d['ExchangeDetection'].ActiveDirectory.ServerCount } catch { $null })
    # AD's serialNumber lags the installed CU; ExSetup.exe on the local host is authoritative
    # (Microsoft's own guidance). Applied here, in Summary, rather than in the AD section, because
    # the AD section runs BEFORE Exchange detection and $Ctx.ExchangeProduct is still null there.
    # Without this a single-server org reports two different labels for the same box - King Springs
    # 15 Sep 2026 gave "CU23" locally and "later than CU23" from AD.
    if ($script:Ctx.OrgServerCount -eq 1 -and $script:Ctx.ExchangeProduct -and $script:Ctx.ExchangeInstalled) {
        $script:Ctx.OrgMinProduct = $script:Ctx.ExchangeProduct
        $script:Ctx.OrgMaxProduct = $script:Ctx.ExchangeProduct
        $s.OrgVersionSource = 'Local ExSetup.exe (authoritative; single-server org)'
    }
    $s.OrgOldestServerVersion = $script:Ctx.OrgMinProduct
    $s.OrgNewestServerVersion = $script:Ctx.OrgMaxProduct
    $s.OrgServerCountByFamily = $script:Ctx.OrgServerCountByFamily

    $s.OnPremUserMailboxCount     = $script:Ctx.OnPremUserMailboxCount
    $s.OnPremMailboxCountAllTypes = $script:Ctx.OnPremMailboxCountAllTypes
    $s.RemoteMailboxCount         = $script:Ctx.RemoteMailboxCount
    $s.RecipientCountSource       = $script:Ctx.RecipientCountSource

    # Public folders on-premises?
    $pfSignals = 0
    try { $pfSignals += Get-SafeCount -Value $d['ExchangeFootprint'].PublicFolderDatabases } catch { }
    try { $pfm = $d['RecipientInventory'].FromExchangeCmdlets['Special_PublicFolder']; if ($pfm -is [int] -and $pfm -gt 0) { $pfSignals += $pfm } } catch { }
    try { $c = $d['RecipientInventory'].FromActiveDirectory.Counts; if ($c -and $c.Contains('PublicFolderMailbox')) { $pfSignals += [int]$c['PublicFolderMailbox'] } } catch { }
    $s.OnPremPublicFolderSignals = $pfSignals

    # SMTP relay determination (findings 19 and 36). Evidence sources: receive connectors,
    # message tracking (SMTP RECEIVE on non-default connectors only), non-Exchange SMTP
    # services. When none of the three could be read the answer is 'unknown', not 'no'.
    $relayConnectors = 0; $anonConnectors = 0; $defaultAnon = 0; $receiveEvents = 0; $receiveEventsTotal = 0
    $trackingAvailable = $false; $connectorsAvailable = $false; $servicesAvailable = $false
    try {
        $rcRaw = $d['NonRecipientWorkloads'].ReceiveConnectors
        if ($rcRaw -isnot [string] -and $null -ne $rcRaw) {
            $connectorsAvailable = $true
            $rcs = @($rcRaw | Where-Object { $_ -is [System.Collections.IDictionary] })
            $relayConnectors = @($rcs | Where-Object { $_['LooksLikeRelayConnector'] -eq $true }).Count
            # Anonymous relay = anonymous Accept-Any-Recipient, or the Anonymous permission group on a
            # CUSTOM connector. The Anonymous group on a default frontend connector is stock 2013+ inbound.
            $anonConnectors  = @($rcs | Where-Object { $_['AnonymousAcceptAnyRecipient'] -eq $true -or ($_['AnonymousUsersPermissionGroup'] -eq $true -and $_['IsDefaultConnectorName'] -ne $true) }).Count
            $defaultAnon     = @($rcs | Where-Object { $_['AnonymousUsersPermissionGroup'] -eq $true -and $_['IsDefaultConnectorName'] -eq $true }).Count
        }
    }
    catch { }
    try {
        $mt = $d['NonRecipientWorkloads'].MessageTracking
        if ($mt -is [System.Collections.IDictionary] -and $mt.Available -eq $true) {
            $trackingAvailable = $true
            $receiveEvents = [int]$mt.SmtpReceiveEventsOnNonDefaultConnectors
            $receiveEventsTotal = [int]$mt.SmtpReceiveEventsTotal
        }
    }
    catch { }
    $sendFromLocal = 0
    try { $sendFromLocal = @($d['NonRecipientWorkloads'].SendConnectors | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['SourcedFromLocalServer'] -eq $true }).Count } catch { }
    $otherSmtp = 0
    try { $osv = $d['NonRecipientWorkloads'].OtherSmtpServices; if ($null -ne $osv -and $osv -isnot [string]) { $servicesAvailable = $true; $otherSmtp = Get-SafeCount -Value $osv } } catch { }
    $evidenceAvailable = ($connectorsAvailable -or $trackingAvailable -or $servicesAvailable)
    $isRelay = $null
    if ($evidenceAvailable) { $isRelay = ($relayConnectors -gt 0 -or $anonConnectors -gt 0 -or $receiveEvents -gt 0 -or $otherSmtp -gt 0) }
    $s.IsSmtpRelay = $isRelay
    $s.SmtpRelayEvidence = [ordered]@{
        EvidenceAvailable                      = $evidenceAvailable
        ReceiveConnectorsReadable              = $connectorsAvailable
        NonDefaultOrAnonymousReceiveConnectors = $relayConnectors
        AnonymousRelayConnectors               = $anonConnectors
        DefaultConnectorsWithAnonymousGroup    = $defaultAnon
        MessageTrackingAvailable               = $trackingAvailable
        SmtpReceiveEventsOnNonDefaultConnectors = $receiveEvents
        SmtpReceiveEventsTotal                 = $receiveEventsTotal
        SendConnectorsSourcedFromThisServer    = $sendFromLocal
        NonExchangeSmtpServices                = $otherSmtp
    }

    $s.HybridConfigured = [bool]$script:Ctx.HybridConfigured
    $s.HybridMode       = $script:Ctx.HybridMode
    $s.EntraConnectOnThisHost = [bool]$script:Ctx.EntraConnectOnThisHost
    $s.EntraConnectHostFromAd = $(try { @($d['EntraConnect'].SyncServerFromAd | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['SyncServer'] } | ForEach-Object { $_['SyncServer'] }) -join ', ' } catch { $null })
    $s.ScheduledTaskCount     = $script:Ctx.ScheduledTaskCount
    $s.AutomationScriptCount  = $script:Ctx.AutomationScriptCount
    $s.ScriptsUsingOnPremOnlyCmdlets = $(try { $d['Automations'].ScriptsUsingOnPremOnlyCmdlets } catch { $null })
    $s.ScriptsUsingCloudModules      = $(try { $d['Automations'].ScriptsUsingCloudModules } catch { $null })
    $s.ScriptsWithCredentialPatterns = $(try { $d['Automations'].ScriptsWithCredentialPatterns } catch { $null })
    $s.ScriptsUsingImportClixmlCredential = $(try { $d['Automations'].ScriptsUsingImportClixmlCredential } catch { $null })
    $s.AutomationDiscoveryTruncated  = [bool]$script:Ctx.AutomationTruncated
    $s.CustomRbacRoleGroups   = $(try { $d['ExchangeFootprint'].Rbac.CustomRoleGroupCount } catch { $null })
    $s.NonExchangeIisApplications = $(try { $d['NonRecipientWorkloads'].Iis.NonExchangeApplicationCount } catch { $null })
    $s.TransportRuleCount     = $(try { $d['NonRecipientWorkloads'].TransportRules.Count } catch { $null })
    $s.TransportRuleEnabledCount = $(try { $d['NonRecipientWorkloads'].TransportRules.EnabledCount } catch { $null })
    $s.JournalRuleCount       = $(try { $d['NonRecipientWorkloads'].JournalRuleCount } catch { $null })
    $s.NonMicrosoftTransportAgentCount = $(try { $d['NonRecipientWorkloads'].NonMicrosoftTransportAgentCount } catch { $null })
    $s.MailboxDatabaseCount   = $(try { $d['ExchangeFootprint'].MailboxDatabaseCount } catch { $null })
    $s.MailboxDatabaseTotalSizeGB = $(try { $d['ExchangeFootprint'].MailboxDatabaseTotalSizeGB } catch { $null })
    $s.DeadlineReached        = [bool]$script:DeadlineHit
    $s.SectionsSkippedAtDeadline = @(foreach ($k in $script:SectionMeta.Keys) { if ($script:SectionMeta[$k].Status -eq 'SKIPPED_DEADLINE') { $k } })

    # --- Blockers / considerations per option -------------------------------------------
    $mbx = $script:Ctx.OnPremUserMailboxCount
    $mbxAll = $script:Ctx.OnPremMailboxCountAllTypes
    if ($null -eq $mbx) { [void]$notes.Add('On-premises mailbox count could not be determined (no Exchange cmdlets and AD query failed or stopped at the deadline). Re-run as an Exchange administrator.') }
    elseif ($mbxAll -gt 0) { [void]$blockers.Add(('Option 2 (standalone Management Tools): {0} on-premises mailbox object(s) remain ({1} user mailboxes). All mailboxes must be in Exchange Online first.' -f $mbxAll, $mbx)) }
    if ($pfSignals -gt 0) { [void]$blockers.Add('Option 2: on-premises public folder databases/mailboxes detected; public folders must be migrated or removed first.') }
    if ($isRelay -eq $true) { [void]$blockers.Add('Option 2: the server appears to receive SMTP (relay/application mail). A replacement relay path (Exchange Online direct send / connector, or another relay) is required before the server can be removed.') }
    elseif ($null -eq $isRelay) { [void]$notes.Add('SMTP relay status is UNKNOWN: receive connectors, message tracking and local SMTP services could not be read in this run. Re-run on the Exchange server as an Exchange administrator before ruling option 2 in or out.') }
    if ($s.CustomRbacRoleGroups -is [int] -and $s.CustomRbacRoleGroups -gt 0) { [void]$notes.Add('Custom RBAC role groups exist; the Management Tools role has no RBAC/EAC, so delegated helpdesk permissions would need to move to Exchange Online or AD ACLs.') }
    if (($s.TransportRuleCount -is [int] -and $s.TransportRuleCount -gt 0) -or ($s.JournalRuleCount -is [int] -and $s.JournalRuleCount -gt 0)) {
        [void]$blockers.Add(('Option 2: {0} transport rule(s) and {1} journal rule(s) exist on-premises. The Management Tools role cannot evaluate them; they must be recreated in Exchange Online or retired before the server is removed.' -f $(if ($s.TransportRuleCount -is [int]) { $s.TransportRuleCount } else { 0 }), $(if ($s.JournalRuleCount -is [int]) { $s.JournalRuleCount } else { 0 })))
    }
    if ($s.NonMicrosoftTransportAgentCount -is [int] -and $s.NonMicrosoftTransportAgentCount -gt 0) { [void]$blockers.Add(('Option 2: {0} non-Microsoft transport agent(s) are registered on this server (mail security, signatures or archiving in the mail path). Their function must move elsewhere before the server can be removed.' -f $s.NonMicrosoftTransportAgentCount)) }

    # Version blockers are driven by the OLDEST server in the organisation (finding 35). A 2016
    # management box in front of 2010 mailbox servers is the realistic 2010-to-SE case and must
    # still raise the blocker.
    $minFamily = $script:Ctx.OrgMinFamily
    if (-not $minFamily) {
        # No AD server list: fall back to the local product.
        if ($script:Ctx.ExchangeVersionKey -eq 'v14' -or $script:Ctx.ExchangeProduct -match '2010') { $minFamily = '2010' }
        elseif ($script:Ctx.ExchangeProduct -match '2013') { $minFamily = '2013' }
        elseif ($script:Ctx.ExchangeProduct -match '2016') { $minFamily = '2016' }
        elseif ($script:Ctx.ExchangeProduct -match '2019') { $minFamily = '2019' }
        elseif ($script:Ctx.ExchangeProduct -match 'Subscription Edition') { $minFamily = 'SE' }
    }
    $famCounts = $script:Ctx.OrgServerCountByFamily
    $famText = $(if ($famCounts -is [System.Collections.IDictionary] -and $famCounts.Count -gt 0) { ' Servers by version: ' + (@(foreach ($k in $famCounts.Keys) { '{0}={1}' -f $k, $famCounts[$k] }) -join ', ') + '.' } else { '' })
    if ($minFamily -in @('2007 or earlier', '2010', '2013')) {
        [void]$blockers.Add(('Option 1 and 2: the oldest Exchange server in the organisation is {0}, which is out of support and cannot coexist with Exchange SE. Every {0} server must be removed via a 2016/2019 hop or a fresh SE build before SE can be introduced (no in-place path).{1}' -f $minFamily, $famText))
    }
    elseif ($minFamily -eq '2016') { [void]$notes.Add('Exchange 2016 cannot upgrade in place to SE; option 1 means a new SE server (legacy upgrade), which suits a new Azure VM.' + $famText) }
    elseif ($minFamily -eq '2019') {
        $minVer = $script:Ctx.OrgMinVersion
        if ($minVer -and $minVer.Build -lt 1544) { [void]$notes.Add('The oldest Exchange 2019 server is below CU14; CU14/CU15 is required before an in-place upgrade to SE.' + $famText) }
        else { [void]$notes.Add('Exchange 2019 CU14/CU15 can upgrade in place to SE.' + $famText) }
    }
    # Finding 17: more than one Exchange server in the org.
    $orgCount = $script:Ctx.OrgServerCount
    if ($orgCount -is [int] -and $orgCount -gt 1) {
        [void]$blockers.Add(('Option 2: the organisation has {0} Exchange servers in Active Directory (Edge servers included). The Management Tools role requires every Exchange server to be uninstalled; this host cannot be replaced in isolation.{1}' -f $orgCount, $famText))
        [void]$notes.Add(('Option 1: {0} Exchange servers exist; relocating this host does not retire the others. Confirm the role of each (mailbox, transport, edge) before scoping.' -f $orgCount))
    }
    if ($script:Ctx.ManagementToolsOnly) { [void]$notes.Add('This host is already a management-tools-only install (no server roles). Options 1 and 2 concern the remaining server(s) in the organisation, not this host.') }
    if ($s.ScriptsUsingOnPremOnlyCmdlets -is [int] -and $s.ScriptsUsingOnPremOnlyCmdlets -gt 0) { [void]$notes.Add(('Option 3 (cloud source of authority): {0} script(s) use on-premises-only Exchange cmdlets (e.g. remote mailbox provisioning) and would need rewriting against Exchange Online/Graph.' -f $s.ScriptsUsingOnPremOnlyCmdlets)) }
    if ($s.EntraConnectOnThisHost) { [void]$notes.Add('Entra Connect runs on this server; it must be relocated (staging-mode swing) before the server is retired or moved.') }
    if ($s.NonExchangeIisApplications -is [int] -and $s.NonExchangeIisApplications -gt 0) { [void]$notes.Add(('{0} non-Exchange IIS application(s) are hosted on this server.' -f $s.NonExchangeIisApplications)) }
    if ($s.ScriptsWithCredentialPatterns -is [int] -and $s.ScriptsWithCredentialPatterns -gt 0) { [void]$notes.Add(('{0} script(s) show hard-coded credential patterns; any rebuild should move them to certificate/managed identity authentication.' -f $s.ScriptsWithCredentialPatterns)) }
    if ($s.ScriptsUsingImportClixmlCredential -is [int] -and $s.ScriptsUsingImportClixmlCredential -gt 0) { [void]$notes.Add(('{0} script(s) load a stored credential with Import-Clixml. DPAPI-protected credentials are bound to the machine and account that created them and will not work on a rehosted server; they must be re-created on the new host or replaced with certificate/managed identity authentication.' -f $s.ScriptsUsingImportClixmlCredential)) }
    if ($s.AutomationDiscoveryTruncated) { [void]$notes.Add('Automation discovery hit a cap or the deadline (see I_Automations.TruncationFlags); the task and script counts are lower bounds.') }
    if (-not $script:Ctx.ExchangeToolsLoaded) { [void]$notes.Add('Exchange cmdlets were not available in this run (method: ' + $script:Ctx.ExchangeToolsMethod + '); connector, hybrid and RBAC detail came from AD only. Re-run on the Exchange server as an Exchange administrator for full detail.') }
    if ($script:FailedSections.Count -gt 0) { [void]$notes.Add('Sections that failed: ' + ($script:FailedSections -join ', ')) }
    if ($s.SectionsSkippedAtDeadline.Count -gt 0) { [void]$notes.Add(('The {0}-minute deadline was reached; sections not run: {1}. Re-run with -MaxMinutes 60 for a complete picture.' -f $script:MaxMinutes, ($s.SectionsSkippedAtDeadline -join ', '))) }

    $s.Blockers = @($blockers.ToArray())
    $s.Considerations = @($notes.ToArray())

    $verdict = 'Insufficient data'
    if ($null -ne $mbx) {
        if ($mbxAll -gt 0) { $verdict = 'On-prem mailboxes remain: option 1 (Azure VM with Exchange SE) or migrate mailboxes first' }
        elseif ($null -eq $isRelay) { $verdict = 'No on-prem mailboxes, but SMTP relay status is unknown (evidence not readable in this run); re-run as Exchange admin before choosing option 2' }
        elseif ($isRelay) { $verdict = 'No on-prem mailboxes but SMTP relay in use: option 2 after relay replacement, or option 1 (Azure VM) to keep relay' }
        elseif ($pfSignals -gt 0) { $verdict = 'No on-prem mailboxes but public folders remain: migrate/remove public folders, then option 2 looks viable' }
        elseif ($blockers.Count -gt 0) { $verdict = 'No on-prem mailboxes or relay, but blockers remain (see list): option 2 after they are cleared, or option 1' }
        else { $verdict = 'Option 2 (Management Tools only) looks viable; option 3 possible; option 1 not required' }
    }
    elseif ($script:Ctx.ExchangeProduct) { $verdict = 'Exchange detected (' + $script:Ctx.ExchangeProduct + ') but recipient counts unavailable; re-run as Exchange admin' }
    if ($script:DeadlineHit -and $verdict -ne 'Insufficient data') { $verdict += ' [partial run: deadline reached]' }
    $s.Verdict = $verdict
    return $s
}

# =======================================================================================
# Text report rendering
# =======================================================================================
function Test-IsScalar {
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $true }
    return $false
}
function Format-Scalar {
    param($Value)
    if ($null -eq $Value) { return '(none)' }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    if ($Value -is [DateTime]) { return (ConvertTo-IsoString -Value $Value) }
    $t = "$Value"
    if ($t -eq '') { return '(empty)' }
    return $t
}
function Write-ReportObject {
    # Depth-capped (finding 31): a Parent/Children cycle in a live .NET/COM object that slipped
    # into a section would otherwise recurse until a StackOverflowException killed the process.
    param($Object, [int]$Indent = 0, [string]$Label = '', [int]$Depth = 0)
    $pad = ' ' * $Indent
    if ($Depth -gt 14) { [void]$script:Report.Add(('{0}{1,-36}: <depth limit reached>' -f $pad, $Label)); return }
    if (Test-IsScalar -Value $Object) {
        if ($Label) { [void]$script:Report.Add(('{0}{1,-36}: {2}' -f $pad, $Label, (Format-Scalar -Value $Object))) } else { [void]$script:Report.Add($pad + (Format-Scalar -Value $Object)) }
        return
    }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Label) { [void]$script:Report.Add("$pad$Label") }
        $child = $(if ($Label) { $Indent + 2 } else { $Indent })
        foreach ($k in @($Object.Keys)) { Write-ReportObject -Object $Object[$k] -Indent $child -Label "$k" -Depth ($Depth + 1) }
        return
    }
    if ($Object -is [System.Collections.IEnumerable]) {
        $arr = @($Object)
        [void]$script:Report.Add(('{0}{1} ({2} item{3})' -f $pad, $Label, $arr.Count, $(if ($arr.Count -eq 1) { '' } else { 's' })))
        $i = 0
        foreach ($item in $arr) {
            $i++
            if ($i -gt 150) { [void]$script:Report.Add(('{0}  ... {1} more item(s) omitted from the text report; see discovery.json' -f $pad, ($arr.Count - 150))); break }
            if (Test-IsScalar -Value $item) { [void]$script:Report.Add(('{0}  - {1}' -f $pad, (Format-Scalar -Value $item))) }
            else { Write-ReportObject -Object $item -Indent ($Indent + 2) -Label "[$i]" -Depth ($Depth + 1) }
        }
        return
    }
    if ($Depth -lt 10 -and ($Object -is [PSCustomObject] -or $null -ne $Object.PSObject)) {
        $d = [ordered]@{}
        foreach ($p in $Object.PSObject.Properties) { $d[$p.Name] = $p.Value }
        Write-ReportObject -Object $d -Indent $Indent -Label $Label -Depth ($Depth + 1)
        return
    }
    [void]$script:Report.Add(('{0}{1,-36}: {2}' -f $pad, $Label, "$Object"))
}

# =======================================================================================
# Output folder resolution (falls back sensibly when run as SYSTEM)
# =======================================================================================
function Resolve-OutputFolder {
    param([string]$Requested)
    $stamp = $script:StartLocal.ToString('yyyyMMdd-HHmmss')
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Requested) { [void]$candidates.Add($Requested) }
    $isServiceProfile = ($env:USERPROFILE -match '\\config\\systemprofile' -or $env:USERPROFILE -match '\\ServiceProfiles\\')
    if ($env:USERPROFILE -and -not $isServiceProfile) {
        $desk = Join-Path $env:USERPROFILE 'Desktop'
        if (Test-Path -LiteralPath $desk) { [void]$candidates.Add($desk) }
    }
    if ($env:ProgramData) { [void]$candidates.Add((Join-Path $env:ProgramData 'CommunifyDiscovery')) }
    if ($env:TEMP) { [void]$candidates.Add($env:TEMP) }
    [void]$candidates.Add((Join-Path $env:SystemDrive 'CommunifyDiscovery'))
    foreach ($parent in $candidates) {
        try {
            $folder = Join-Path $parent ('CommunifyDiscovery_' + $stamp)
            [void][System.IO.Directory]::CreateDirectory($folder)
            $probe = Join-Path $folder '.write-test'
            [System.IO.File]::WriteAllText($probe, 'ok')
            [System.IO.File]::Delete($probe)
            return $folder
        }
        catch { continue }
    }
    throw 'No writable output location could be found.'
}

# =======================================================================================
# MAIN
# =======================================================================================
if (-not $script:Compact) {
    Write-ConsoleLine -Text '=====================================================================' -Colour 'Cyan'
    Write-ConsoleLine -Text ' BiTS Technology Group - Exchange / Entra Connect discovery (READ-ONLY)' -Colour 'Cyan'
    Write-ConsoleLine -Text ('  Version {0}' -f $script:ScriptVersion) -Colour 'Cyan'
    Write-ConsoleLine -Text '=====================================================================' -Colour 'Cyan'
    Write-ConsoleLine -Text ' This script makes NO changes. It reads Exchange, Active Directory, Entra' -Colour 'Gray'
    Write-ConsoleLine -Text ' Connect, host, network and scheduled-task configuration and writes the' -Colour 'Gray'
    Write-ConsoleLine -Text ' results to files for you to review before sending them to BiTS.' -Colour 'Gray'
    Write-ConsoleLine -Text ' It collects counts, versions and configuration only: no mailbox names,' -Colour 'Gray'
    Write-ConsoleLine -Text ' addresses, memberships, message content or credential values.' -Colour 'Gray'
    Write-ConsoleLine -Text '' -Colour 'Gray'
}

$script:OutputFolder = $null
try { $script:OutputFolder = Resolve-OutputFolder -Requested $OutputPath }
catch { Write-ConsoleLine -Text ('[FAIL] Output folder: ' + (ConvertTo-SafeError -ErrorRecord $_)) -Colour 'Red' }
$script:JsonBytes  = 0
$script:JsonWriteError = $null
$script:ZipPath    = $null
$script:MainError  = $null
$script:Utf8NoBom  = New-Object System.Text.UTF8Encoding($false)

# =======================================================================================
# Output assembly and writers. Write-DiscoveryFiles -Partial rewrites discovery.json after
# every section (finding 20); the final call also writes the report, the summary and the zip.
# =======================================================================================
function Get-RunMetadata {
    param([switch]$Partial)
    $elapsed = [DateTime]::UtcNow - $script:StartUtc
    $scriptHash = $null
    try { if ($PSCommandPath) { $scriptHash = Get-FileSha256Prefix -Path $PSCommandPath } } catch { }
    # Access-rights warnings surfaced explicitly (SYSTEM / non-admin runs). Warnings now carry a
    # reason code rather than the exception text, so the match is on the code.
    $denied = @()
    try {
        foreach ($k in $script:SectionMeta.Keys) { foreach ($w in @($script:SectionMeta[$k].Warnings)) { if ($w -match '\bAccessDenied\b') { $denied += ('{0}: {1}' -f $k, $w) } } }
    }
    catch { }
    $script:Ctx.AccessDeniedWarnings = $denied
    [ordered]@{
        ScriptName            = 'Invoke-CommunifyDiscovery.ps1'
        ScriptVersion         = $script:ScriptVersion
        ScriptSha256Prefix    = $scriptHash
        Author                = 'BiTS Technology Group'
        ReadOnly              = $true
        PartialOutput         = [bool]$Partial
        RunCompleted          = [bool]$script:RunCompleted
        MaxMinutes            = $script:MaxMinutes
        DeadlineReached       = [bool]$script:DeadlineHit
        StartTimeUtc          = $script:StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        StartTimeLocal        = ConvertTo-IsoString -Value $script:StartLocal
        ElapsedSeconds        = [math]::Round($elapsed.TotalSeconds, 1)
        PowerShellVersion     = "$($PSVersionTable.PSVersion)"
        PowerShellEdition     = $(if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' })
        Is64BitProcess        = [Environment]::Is64BitProcess
        OperatingSystem       = $(try { $script:Sections['Host'].OperatingSystem.Caption + ' (' + $script:Sections['Host'].OperatingSystem.Version + ')' } catch { $null })
        IsElevated            = $(try { $script:Sections['Host'].RunningAs.IsElevated } catch { $null })
        RunningAs             = $(try { $script:Sections['Host'].RunningAs.Account } catch { $null })
        IsDomainJoined        = $script:Ctx.IsDomainJoined
        ExchangeCmdletLoadMethod = $script:Ctx.ExchangeToolsMethod
        ExchangeToolsMode     = $script:Ctx.ExchangeToolsMode
        Parameters            = [ordered]@{ RedactHostnames = $script:Redact; SkipNetworkTests = $script:SkipNet; MessageTrackingDays = $script:TrackingDays; MaxMinutes = $script:MaxMinutes; Quiet = [bool]$Quiet; CompactOutput = $script:Compact }
        OutputFolder          = Protect-FilePath -Value $script:OutputFolder
        UnexpectedError       = $script:MainError
        FailedSections        = @($script:FailedSections.ToArray())
        AccessDeniedWarnings  = @($script:Ctx.AccessDeniedWarnings)
        SectionStatus         = $script:SectionMeta
    }
}

function Get-OutputObject {
    param([switch]$Partial)
    [ordered]@{
        'A_RunMetadata'           = Get-RunMetadata -Partial:$Partial
        'B_Host'                  = $script:Sections['Host']
        'C_ExchangeDetection'     = $script:Sections['ExchangeDetection']
        'C_ExchangeFootprint'     = $script:Sections['ExchangeFootprint']
        'D_NonRecipientWorkloads' = $script:Sections['NonRecipientWorkloads']
        'E_RecipientInventory'    = $script:Sections['RecipientInventory']
        'F_Hybrid'                = $script:Sections['Hybrid']
        'G_EntraConnect'          = $script:Sections['EntraConnect']
        'H_ActiveDirectory'       = $script:Sections['ActiveDirectory']
        'I_Automations'           = $script:Sections['Automations']
        'J_Network'               = $script:Sections['Network']
        'K_Licensing'             = $script:Sections['Licensing']
        'Summary'                 = $script:Sections['Summary']
    }
}

function Write-DiscoveryFiles {
    param([switch]$Partial)
    if (-not $script:OutputFolder) { return }
    $output = Get-OutputObject -Partial:$Partial

    # discovery.json (always; rewritten after every section so a killed run keeps its data).
    # The tree MUST be reduced to primitives first. ConvertTo-Json chokes on a live .NET or COM
    # object left in a section (verified on King Springs 15 Sep 2026: the ExchangeDetection section
    # failed to serialise, the whole-object write threw, and discovery.json was silently left as a
    # 14 KB partial from an earlier section while the run reported success).
    $script:JsonWriteError = $null
    try {
        $safe = ConvertTo-SafeValue -Value $output
        $json = ConvertTo-Json -InputObject $safe -Depth 20
        $jsonPath = Join-Path $script:OutputFolder 'discovery.json'
        [System.IO.File]::WriteAllText($jsonPath, $json, $script:Utf8NoBom)
        $script:JsonBytes = (Get-Item -LiteralPath $jsonPath).Length
    }
    catch {
        $script:JsonWriteError = ConvertTo-SafeError -ErrorRecord $_
        # Never silent, partial run or not: an incomplete discovery.json that still reports SUCCESS
        # is the failure mode this guards against.
        if (-not $Partial) { Write-Status -Level 'FAIL' -Message ('discovery.json could not be written: ' + $script:JsonWriteError) }
    }
    if ($Partial) { return }

    # discovery-report.txt
    try {
        $script:Report.Clear()
        [void]$script:Report.Add('BiTS Technology Group - Exchange / Entra Connect discovery report (READ-ONLY)')
        [void]$script:Report.Add(('Generated {0} local / {1} UTC by script version {2}' -f (ConvertTo-IsoString -Value $script:StartLocal), $script:StartUtc.ToString('yyyy-MM-dd HH:mm:ss'), $script:ScriptVersion))
        [void]$script:Report.Add('Review every section below before sending this folder to BiTS. Values shown as id:xxxxxxxxxxxx are salted one-way hashes unique to this run.')
        if ($script:DeadlineHit) { [void]$script:Report.Add(('NOTE: the {0}-minute deadline was reached; sections marked SKIPPED_DEADLINE did not run and some counts are lower bounds.' -f $script:MaxMinutes)) }
        [void]$script:Report.Add('')
        foreach ($k in $output.Keys) {
            [void]$script:Report.Add('=' * 100)
            $meta = $null
            foreach ($mk in $script:SectionMeta.Keys) { if ($k -like ('*' + $mk)) { $meta = $script:SectionMeta[$mk] } }
            if ($k -eq 'A_RunMetadata') { [void]$script:Report.Add('A. RUN METADATA') }
            elseif ($meta) { [void]$script:Report.Add(('{0}   [{1}, {2} ms]' -f $meta.Name.ToUpperInvariant(), $meta.Status, $meta.ElapsedMs)) }
            else { [void]$script:Report.Add($k) }
            [void]$script:Report.Add('=' * 100)
            if ($meta -and $meta.Error) { [void]$script:Report.Add('  SECTION ERROR: ' + $meta.Error) }
            if ($meta -and @($meta.Warnings).Count -gt 0) { foreach ($w in @($meta.Warnings)) { [void]$script:Report.Add('  WARNING: ' + $w) } }
            if ($null -eq $output[$k]) { [void]$script:Report.Add('  (section not run)') }
            else { Write-ReportObject -Object $output[$k] -Indent 0 }
            [void]$script:Report.Add('')
        }
        [System.IO.File]::WriteAllLines((Join-Path $script:OutputFolder 'discovery-report.txt'), $script:Report.ToArray(), $script:Utf8NoBom)
    }
    catch { Write-Status -Level 'FAIL' -Message ('discovery-report.txt could not be written: ' + (ConvertTo-SafeError -ErrorRecord $_)) }

    # discovery-summary.txt
    try {
        $sum = $script:Sections['Summary']
        $lines = New-Object System.Collections.Generic.List[string]
        [void]$lines.Add('BiTS Technology Group - discovery summary (at a glance)')
        [void]$lines.Add(('Host: {0}   Generated: {1}   Script version: {2}' -f (Protect-Hostname -Value $env:COMPUTERNAME), (ConvertTo-IsoString -Value $script:StartLocal), $script:ScriptVersion))
        if ($script:DeadlineHit) { [void]$lines.Add(('PARTIAL RUN: the {0}-minute deadline was reached; see "Section status" below.' -f $script:MaxMinutes)) }
        [void]$lines.Add('')
        if ($sum -is [System.Collections.IDictionary]) {
            foreach ($k in @('ExchangeProduct', 'ExchangeVersionString', 'ExchangeInstalledLocally', 'ManagementToolsOnlyInstall', 'ManagementInterfaceObserved', 'ManagementInterfaceByVersion', 'OrganizationName', 'ExchangeServerCountInOrg', 'OrgOldestServerVersion', 'OrgNewestServerVersion', 'ExchangeCmdletsLoaded', 'ExchangeCmdletLoadMethod', 'OnPremUserMailboxCount', 'OnPremMailboxCountAllTypes', 'RemoteMailboxCount', 'RecipientCountSource', 'OnPremPublicFolderSignals', 'MailboxDatabaseCount', 'MailboxDatabaseTotalSizeGB', 'IsSmtpRelay', 'TransportRuleCount', 'TransportRuleEnabledCount', 'JournalRuleCount', 'NonMicrosoftTransportAgentCount', 'HybridConfigured', 'HybridMode', 'EntraConnectOnThisHost', 'EntraConnectHostFromAd', 'ScheduledTaskCount', 'AutomationScriptCount', 'ScriptsUsingOnPremOnlyCmdlets', 'ScriptsUsingCloudModules', 'ScriptsWithCredentialPatterns', 'ScriptsUsingImportClixmlCredential', 'AutomationDiscoveryTruncated', 'CustomRbacRoleGroups', 'NonExchangeIisApplications', 'DeadlineReached')) {
                if ($sum.Contains($k)) {
                    $val = $sum[$k]
                    if ($k -eq 'IsSmtpRelay' -and $null -eq $val) { $val = 'Unknown (no evidence readable)' }
                    [void]$lines.Add(('{0,-36}: {1}' -f $k, (Format-Scalar -Value $val)))
                }
            }
            [void]$lines.Add('')
            [void]$lines.Add('SMTP relay evidence:')
            foreach ($k in @($sum.SmtpRelayEvidence.Keys)) { [void]$lines.Add(('  {0,-42}: {1}' -f $k, (Format-Scalar -Value $sum.SmtpRelayEvidence[$k]))) }
            [void]$lines.Add('')
            [void]$lines.Add('Blockers detected:')
            if (@($sum.Blockers).Count -eq 0) { [void]$lines.Add('  (none)') } else { foreach ($b in @($sum.Blockers)) { [void]$lines.Add('  - ' + $b) } }
            [void]$lines.Add('')
            [void]$lines.Add('Considerations:')
            if (@($sum.Considerations).Count -eq 0) { [void]$lines.Add('  (none)') } else { foreach ($c in @($sum.Considerations)) { [void]$lines.Add('  - ' + $c) } }
            [void]$lines.Add('')
            [void]$lines.Add('Verdict: ' + $sum.Verdict)
        }
        else { [void]$lines.Add('Summary section did not run or failed; see discovery-report.txt.') }
        [void]$lines.Add('')
        [void]$lines.Add('Section status:')
        foreach ($k in $script:SectionMeta.Keys) { $m = $script:SectionMeta[$k]; [void]$lines.Add(('  {0,-24} {1,-16} {2,7} ms  {3}' -f $k, $m.Status, $m.ElapsedMs, $(if ($m.Error) { $m.Error } elseif (@($m.Warnings).Count -gt 0) { "$(@($m.Warnings).Count) warning(s)" } else { '' }))) }
        [System.IO.File]::WriteAllLines((Join-Path $script:OutputFolder 'discovery-summary.txt'), $lines.ToArray(), $script:Utf8NoBom)
    }
    catch { Write-Status -Level 'FAIL' -Message ('discovery-summary.txt could not be written: ' + (ConvertTo-SafeError -ErrorRecord $_)) }

    # Optional zip
    try {
        if (Get-Command -Name 'Compress-Archive' -ErrorAction SilentlyContinue) {
            $zip = $script:OutputFolder + '.zip'
            Compress-Archive -Path (Join-Path $script:OutputFolder '*') -DestinationPath $zip -Force -ErrorAction Stop
            $script:ZipPath = $zip
        }
    }
    catch { Write-Status -Level 'WARN' -Message ('Zip not created: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
}

# =======================================================================================
# Collection. The whole flow sits in try/finally: whatever happens (an unexpected error,
# Ctrl-C, the deadline), the Summary is computed from what exists and the files are
# written. discovery.json has also been rewritten after every section along the way.
# =======================================================================================
try {
    # Run order follows data dependencies; the report is assembled in A-K order afterwards.
    Invoke-Section -Key 'Host'                  -Name 'B. Host / server sizing'                 -Script { Get-HostSection }
    Invoke-Section -Key 'ActiveDirectory'       -Name 'H. Active Directory'                     -Script { Get-ActiveDirectorySection }
    Invoke-Section -Key 'ExchangeDetection'     -Name 'C1. Exchange detection (registry + AD)'  -Script { Get-ExchangeDetectionSection }

    Write-Status -Level 'HEAD' -Message '--- Loading Exchange management tools (session-scoped) ---'
    if (Test-PastDeadline) { Write-Status -Level 'SKIP' -Message 'Exchange tools loader skipped: deadline reached' }
    else {
        try { . $script:ExchangeToolsLoader } catch { Write-Status -Level 'WARN' -Message ('Exchange tools loader: ' + (ConvertTo-SafeError -ErrorRecord $_)) }
        if ($script:Ctx.ExchangeToolsLoaded) { Write-Status -Level 'OK' -Message ('Exchange cmdlets loaded via ' + $script:Ctx.ExchangeToolsMethod) }
        else { Write-Status -Level 'WARN' -Message 'Exchange cmdlets not available; continuing in AD-only mode.' }
    }

    Invoke-Section -Key 'ExchangeFootprint'     -Name 'C2. Exchange footprint'                  -Script { Get-ExchangeFootprintSection }
    Invoke-Section -Key 'NonRecipientWorkloads' -Name 'D. Non-recipient workloads (SMTP relay, transport, IIS)' -Script { Get-NonRecipientWorkloadSection }
    Invoke-Section -Key 'RecipientInventory'    -Name 'E. Recipient inventory (counts only)'     -Script { Get-RecipientInventorySection }
    Invoke-Section -Key 'Hybrid'                -Name 'F. Hybrid configuration'                 -Script { Get-HybridSection }
    Invoke-Section -Key 'EntraConnect'          -Name 'G. Entra Connect'                        -Script { Get-EntraConnectSection }
    Invoke-Section -Key 'Automations'           -Name 'I. Automations (tasks, scripts, modules)' -Script { Get-AutomationSection }
    Invoke-Section -Key 'Network'               -Name 'J. Network / Azure readiness'            -Script { Get-NetworkSection }
    Invoke-Section -Key 'Licensing'             -Name 'K. Licensing posture signals'            -Script { Get-LicensingSection }
    $script:RunCompleted = $true
}
catch {
    $script:MainError = ConvertTo-SafeError -ErrorRecord $_
    Write-Status -Level 'FAIL' -Message ('Collection stopped unexpectedly: ' + $script:MainError)
}
finally {
    try { Invoke-Section -Key 'Summary' -Name 'Summary' -Script { Get-SummarySection } -AlwaysRun } catch { }
    try { Write-DiscoveryFiles } catch { }
    # Close the implicit remoting session so it does not hold an Exchange throttling slot.
    if ($null -ne $script:ExchangeSession) { try { Remove-PSSession -Session $script:ExchangeSession -ErrorAction SilentlyContinue } catch { } }
}

$runMeta = Get-RunMetadata

# --- Console close-out -------------------------------------------------------------------
if ($script:Compact) {
    # Compact, machine-readable block for RMM capture. Priority 1 lines are never trimmed;
    # blockers are priority 1 (finding 14) so they survive the trim.
    $sum = $script:Sections['Summary']
    $lines = New-Object System.Collections.ArrayList
    function Push-CompactLine { param([int]$Priority, [string]$Key, $Value)
        $v = Format-Scalar -Value $Value
        $v = $v -replace '[\r\n]+', ' '
        if ($v.Length -gt 160) { $v = $v.Substring(0, 160) }
        [void]$lines.Add(@{ P = $Priority; Text = ('{0}={1}' -f $Key, $v) })
    }
    Push-CompactLine 1 'script_version' $script:ScriptVersion
    Push-CompactLine 1 'ps_version' "$($PSVersionTable.PSVersion)"
    Push-CompactLine 1 'os_caption' $runMeta.OperatingSystem
    Push-CompactLine 1 'elapsed_seconds' $runMeta.ElapsedSeconds
    Push-CompactLine 1 'run_completed' $runMeta.RunCompleted
    Push-CompactLine 1 'deadline_reached' $runMeta.DeadlineReached
    Push-CompactLine 2 'is_64bit_process' $runMeta.Is64BitProcess
    Push-CompactLine 2 'running_as' $runMeta.RunningAs
    Push-CompactLine 2 'is_elevated' $runMeta.IsElevated
    Push-CompactLine 2 'is_domain_joined' $runMeta.IsDomainJoined
    Push-CompactLine 1 'exchange_detection_method' $(if ($script:Ctx.ExchangeInstalled) { 'registry+exsetup' } elseif ($script:Ctx.ExchangeProduct) { 'active-directory' } else { 'none' })
    Push-CompactLine 1 'exchange_version' $script:Ctx.ExchangeProduct
    Push-CompactLine 1 'exchange_build' $script:Ctx.ExchangeVersionString
    Push-CompactLine 1 'org_oldest_server_version' $script:Ctx.OrgMinProduct
    Push-CompactLine 2 'org_newest_server_version' $script:Ctx.OrgMaxProduct
    Push-CompactLine 1 'exchange_org_name' $(if ($sum -is [System.Collections.IDictionary]) { $sum.OrganizationName } else { $null })
    Push-CompactLine 1 'exchange_server_count_in_org' $(if ($sum -is [System.Collections.IDictionary]) { $sum.ExchangeServerCountInOrg } else { $null })
    Push-CompactLine 1 'exchange_cmdlets_loaded' $script:Ctx.ExchangeToolsMethod
    Push-CompactLine 2 'exchange_tools_mode' $script:Ctx.ExchangeToolsMode
    Push-CompactLine 1 'management_tools_only_install' $script:Ctx.ManagementToolsOnly
    Push-CompactLine 1 'management_interface_observed' $script:Ctx.ManagementInterfaceObserved
    Push-CompactLine 2 'management_interface_by_version' $(if ($sum -is [System.Collections.IDictionary]) { $sum.ManagementInterfaceByVersion } else { $null })
    Push-CompactLine 1 'onprem_user_mailbox_count' $script:Ctx.OnPremUserMailboxCount
    Push-CompactLine 1 'onprem_mailbox_count_all_types' $script:Ctx.OnPremMailboxCountAllTypes
    Push-CompactLine 2 'remote_mailbox_count' $script:Ctx.RemoteMailboxCount
    Push-CompactLine 2 'recipient_count_source' $script:Ctx.RecipientCountSource
    try {
        $rc = $null
        $inv = $script:Sections['RecipientInventory']
        if ($inv.FromExchangeCmdlets -is [System.Collections.IDictionary] -and $inv.FromExchangeCmdlets.Contains('ByRecipientTypeDetails') -and $inv.FromExchangeCmdlets.ByRecipientTypeDetails -is [System.Collections.IDictionary]) { $rc = $inv.FromExchangeCmdlets.ByRecipientTypeDetails }
        elseif ($inv.FromActiveDirectory -is [System.Collections.IDictionary] -and $inv.FromActiveDirectory.Contains('Counts')) { $rc = $inv.FromActiveDirectory.Counts }
        if ($rc) { foreach ($k in @($rc.Keys)) { if ($k -ne 'Total' -and $k -ne 'StoppedAtDeadline') { Push-CompactLine 3 ('recipient.' + $k) $rc[$k] } } }
    }
    catch { }
    if ($sum -is [System.Collections.IDictionary]) {
        Push-CompactLine 1 'is_smtp_relay' $(if ($null -eq $sum.IsSmtpRelay) { 'Unknown' } else { $sum.IsSmtpRelay })
        Push-CompactLine 1 'smtp_relay_receive_connector_evidence' $sum.SmtpRelayEvidence.NonDefaultOrAnonymousReceiveConnectors
        Push-CompactLine 2 'smtp_relay_anonymous_connectors' $sum.SmtpRelayEvidence.AnonymousRelayConnectors
        Push-CompactLine 2 'smtp_relay_receive_events_nondefault' $sum.SmtpRelayEvidence.SmtpReceiveEventsOnNonDefaultConnectors
        Push-CompactLine 2 'smtp_relay_receive_events_total' $sum.SmtpRelayEvidence.SmtpReceiveEventsTotal
        Push-CompactLine 2 'smtp_relay_other_services' $sum.SmtpRelayEvidence.NonExchangeSmtpServices
        Push-CompactLine 1 'transport_rule_count' $sum.TransportRuleCount
        Push-CompactLine 1 'journal_rule_count' $sum.JournalRuleCount
        Push-CompactLine 2 'non_microsoft_transport_agents' $sum.NonMicrosoftTransportAgentCount
        Push-CompactLine 2 'mailbox_database_count' $sum.MailboxDatabaseCount
        Push-CompactLine 1 'entra_connect_on_this_host' $sum.EntraConnectOnThisHost
        Push-CompactLine 2 'entra_connect_host_from_ad' $sum.EntraConnectHostFromAd
        Push-CompactLine 1 'scheduled_task_count' $sum.ScheduledTaskCount
        Push-CompactLine 1 'automation_script_count' $sum.AutomationScriptCount
        Push-CompactLine 2 'scripts_using_onprem_only_cmdlets' $sum.ScriptsUsingOnPremOnlyCmdlets
        Push-CompactLine 2 'scripts_using_cloud_modules' $sum.ScriptsUsingCloudModules
        Push-CompactLine 2 'scripts_using_import_clixml_credential' $sum.ScriptsUsingImportClixmlCredential
        Push-CompactLine 2 'automation_discovery_truncated' $sum.AutomationDiscoveryTruncated
        Push-CompactLine 1 'hybrid_configured' $sum.HybridConfigured
        Push-CompactLine 2 'hybrid_mode' $sum.HybridMode
        Push-CompactLine 2 'onprem_public_folder_signals' $sum.OnPremPublicFolderSignals
        Push-CompactLine 2 'custom_rbac_role_groups' $sum.CustomRbacRoleGroups
        Push-CompactLine 2 'sections_skipped_at_deadline' (@($sum.SectionsSkippedAtDeadline) -join ',')
        $bi = 0; foreach ($b in @($sum.Blockers)) { $bi++; Push-CompactLine 1 ('blocker.' + $bi) $b }
    }
    Push-CompactLine 1 'output_folder' (Protect-FilePath -Value $script:OutputFolder)
    Push-CompactLine 1 'discovery_json_bytes' $script:JsonBytes
    if ($script:JsonWriteError) { Push-CompactLine 1 'discovery_json_write_error' $script:JsonWriteError }
    # Per-section serialised size. A section that collected nothing is otherwise indistinguishable
    # from one that collected plenty, because the counts are reported separately from the payload.
    # Measure what actually lands in discovery.json, i.e. post-sanitisation. One line per section:
    # a single joined line is cut by the per-line cap before it reaches the later sections, which is
    # exactly where unexplained size tends to hide.
    $sizes = Invoke-Guarded -What 'Section sizes' -Script {
        $d = [ordered]@{}
        foreach ($k in $script:Sections.Keys) {
            $n = 0
            try { $n = (ConvertTo-Json -InputObject (ConvertTo-SafeValue -Value $script:Sections[$k]) -Depth 20 -Compress).Length } catch { $n = -1 }
            $d[$k] = $n
        }
        $d
    }
    if ($sizes -is [System.Collections.IDictionary]) {
        # NOTE: these are COMPRESSED sizes. discovery.json is written pretty-printed for readability
        # (the client is expected to review it), which costs roughly 3.8x in indentation - so the sum
        # of these lines will be far smaller than discovery_json_bytes. That is expected, not a fault.
        foreach ($k in $sizes.Keys) { Push-CompactLine 2 ('json_bytes_compressed.' + $k) $sizes[$k] }
    }
    Push-CompactLine 2 'zip_created' ([bool]$script:ZipPath)
    if ($script:MainError) { Push-CompactLine 1 'unexpected_error' $script:MainError }
    foreach ($k in $script:SectionMeta.Keys) {
        $m = $script:SectionMeta[$k]
        $reason = ''
        if ($m.Error) { $reason = $m.Error } elseif (@($m.Warnings).Count -gt 0) { $reason = @($m.Warnings)[0]; if (@($m.Warnings).Count -gt 1) { $reason = ('{0} (+{1} more)' -f $reason, (@($m.Warnings).Count - 1)) } }
        $reason = $reason -replace '[\r\n]+', ' '
        if ($reason.Length -gt 120) { $reason = $reason.Substring(0, 120) }
        $text = $m.Status; if ($reason) { $text = $text + ':' + $reason }
        [void]$lines.Add(@{ P = 1; Text = ('section.{0}={1}' -f $k, $text) })
    }
    $verdictText = $(if ($sum -is [System.Collections.IDictionary]) { $sum.Verdict } else { 'Summary failed' })
    $budget = 7600
    $trimmed = $false
    $tail = @(('VERDICT=' + $verdictText), 'TRUNCATION_GUARD=END_OF_OUTPUT')
    $tailBytes = 0; foreach ($t in $tail) { $tailBytes += [System.Text.Encoding]::UTF8.GetByteCount($t) + 2 }
    $tailBytes += 30   # room for COMPACT_OUTPUT_TRIMMED=true
    for ($p = 3; $p -ge 2; $p--) {
        $total = 0; foreach ($l in $lines) { $total += [System.Text.Encoding]::UTF8.GetByteCount($l.Text) + 2 }
        if (($total + $tailBytes) -le $budget) { break }
        # drop lowest-priority lines from the end until within budget
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            if ($lines[$i].P -eq $p) {
                $lines.RemoveAt($i); $trimmed = $true
                $total = 0; foreach ($l in $lines) { $total += [System.Text.Encoding]::UTF8.GetByteCount($l.Text) + 2 }
                if (($total + $tailBytes) -le $budget) { break }
            }
        }
    }
    foreach ($l in $lines) { Write-Output $l.Text }
    if ($trimmed) { Write-Output 'COMPACT_OUTPUT_TRIMMED=true' }
    Write-Output ('VERDICT=' + $verdictText)
    Write-Output 'TRUNCATION_GUARD=END_OF_OUTPUT'
}
else {
    # Interactive close-out. The real output path is shown here (and only here) because the
    # operator has to find the folder; the files and the RMM block carry the protected form.
    Write-ConsoleLine -Text '' -Colour 'Gray'
    Write-ConsoleLine -Text '=====================================================================' -Colour 'Cyan'
    Write-ConsoleLine -Text (' Discovery {0} in {1} seconds.' -f $(if ($script:RunCompleted) { 'complete' } else { 'ended early' }), $runMeta.ElapsedSeconds) -Colour 'Cyan'
    if ($script:DeadlineHit) { Write-ConsoleLine -Text (' The {0}-minute deadline was reached; some sections were skipped or cut short (see discovery-summary.txt).' -f $script:MaxMinutes) -Colour 'Yellow' }
    if ($script:MainError) { Write-ConsoleLine -Text (' Collection stopped unexpectedly: ' + $script:MainError) -Colour 'Red' }
    if ($script:FailedSections.Count -gt 0) { Write-ConsoleLine -Text (' Sections that failed: ' + ($script:FailedSections -join ', ')) -Colour 'Yellow' }
    if (@($script:Ctx.AccessDeniedWarnings).Count -gt 0) { Write-ConsoleLine -Text (' {0} access-denied warning(s): re-run as an Exchange administrator for full detail.' -f @($script:Ctx.AccessDeniedWarnings).Count) -Colour 'Yellow' }
    if ($script:OutputFolder) {
        Write-ConsoleLine -Text (' Output folder : ' + $script:OutputFolder) -Colour 'Green'
        if ($script:ZipPath) { Write-ConsoleLine -Text (' Zip file      : ' + $script:ZipPath) -Colour 'Green' }
        Write-ConsoleLine -Text '' -Colour 'Gray'
        Write-ConsoleLine -Text ' Please open discovery-report.txt and review every section before' -Colour 'White'
        Write-ConsoleLine -Text ' returning the folder (or the zip) to BiTS Technology Group.' -Colour 'White'
        Write-ConsoleLine -Text ' discovery-summary.txt gives the at-a-glance feasibility read.' -Colour 'White'
    }
    else { Write-ConsoleLine -Text ' No output could be written (no writable folder found).' -Colour 'Red' }
    Write-ConsoleLine -Text '=====================================================================' -Colour 'Cyan'
}
