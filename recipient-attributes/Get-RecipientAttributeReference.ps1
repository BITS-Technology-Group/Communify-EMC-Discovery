<#
.SYNOPSIS
    Read-only collection of the Exchange-related Active Directory attributes on mail
    objects, so that provisioning automation can be rewritten to write those attributes
    directly instead of calling on-premises Exchange cmdlets.

.DESCRIPTION
    When an on-premises Exchange server is retired, cmdlets such as New-RemoteMailbox and
    New-DistributionGroup are no longer available. The objects they used to create are
    ordinary Active Directory objects carrying a specific set of Exchange attributes, and
    provisioning can continue by writing those attributes with the ActiveDirectory module.

    Getting that right requires knowing exactly which attribute values the existing objects
    carry, rather than assuming them. This script reads the directory and reports, for each
    distinct combination of Exchange attribute values it finds, how many objects carry it
    and one example object in full.

    It is READ ONLY. It uses only Get-* cmdlets from the ActiveDirectory module. It makes no
    change to Active Directory, Exchange, Entra Connect or Windows, it does not contact the
    Exchange server, and it does not sign in to any cloud service. The only files it writes
    are its own two output files, in a folder it creates.

    It does not need to run on the Exchange server. Any domain-joined machine with the
    ActiveDirectory PowerShell module will do, including a domain controller or a management
    workstation with RSAT installed.

.PARAMETER Server
    Domain controller to read from. Defaults to an automatically discovered one.

.PARAMETER SearchBase
    Limits the search to one part of the directory, for example an organisational unit.
    Defaults to the whole domain.

.PARAMETER Redact
    Masks the local part of SMTP addresses, account names and display names in the output,
    keeping the structure and all Exchange attribute values intact. Organisational unit
    paths are always kept, because the rewrite needs to know where objects are created.

.PARAMETER OutputPath
    Folder to write the output into. Defaults to the Desktop, then ProgramData, then TEMP.

.PARAMETER ExamplesPerPattern
    How many example objects to include per distinct attribute pattern. Default 1.

.PARAMETER AdditionalGroup
    Names of specific groups to report on, for example a licensing group that provisioning
    adds new accounts to. Reported as found or not found, with membership counts only.

.PARAMETER SkipConflictCheck
    Skips the duplicate address and alias check, which is the slowest part on a large
    directory.

.PARAMETER Stdout
    Writes the report to the console and creates no files at all. Intended for running the
    script through a remote management tool, where the output is read from the job result
    rather than from disk.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-RecipientAttributeReference.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-RecipientAttributeReference.ps1 -Redact

.NOTES
    Version 1.2.1
    Requires Windows PowerShell 5.1 or later and the ActiveDirectory module.
#>

[CmdletBinding()]
param(
    [string] $Server,
    [string] $SearchBase,
    [switch] $Redact,
    [string] $OutputPath,
    [ValidateRange(1, 5)]
    [int] $ExamplesPerPattern = 1,
    [string[]] $AdditionalGroup,
    [switch] $SkipConflictCheck,
    [switch] $Stdout
)

$ErrorActionPreference = 'Stop'
$script:Version = '1.2.1'

# ---------------------------------------------------------------------------
# Attribute sets
# ---------------------------------------------------------------------------

# Attributes that define what kind of recipient an object is, plus the ones that
# provisioning has to set for Entra Connect to present the object correctly to
# Exchange Online.
$UserProperties = @(
    'displayName', 'sAMAccountName', 'userPrincipalName', 'mail', 'mailNickname',
    'targetAddress', 'proxyAddresses', 'legacyExchangeDN', 'extensionAttribute1',
    'msExchRecipientDisplayType', 'msExchRecipientTypeDetails', 'msExchRemoteRecipientType',
    'msExchVersion', 'msExchMailboxGuid', 'msExchArchiveGUID', 'msExchArchiveName',
    'msExchUserAccountControl', 'msExchWhenMailboxCreated', 'msExchPoliciesExcluded',
    'msExchHideFromAddressLists', 'showInAddressBook', 'homeMDB', 'homeMTA',
    'msExchHomeServerName', 'internetEncoding', 'employeeID', 'employeeType',
    'userAccountControl', 'whenCreated', 'whenChanged', 'distinguishedName'
)

$GroupProperties = @(
    'displayName', 'sAMAccountName', 'mail', 'mailNickname', 'targetAddress',
    'proxyAddresses', 'legacyExchangeDN', 'groupType', 'groupCategory', 'groupScope',
    'msExchRecipientDisplayType', 'msExchRecipientTypeDetails', 'msExchVersion',
    'msExchRequireAuthToSendTo', 'msExchGroupJoinRestriction', 'msExchGroupDepartRestriction',
    'msExchHideFromAddressLists', 'msExchPoliciesExcluded', 'msExchCoManagedByLink',
    'reportToOriginator', 'reportToOwner', 'oOFReplyToOriginator', 'authOrig', 'unauthOrig',
    'dLMemSubmitPerms', 'dLMemRejectPerms', 'managedBy', 'showInAddressBook',
    'info', 'description', 'whenCreated', 'whenChanged', 'distinguishedName'
)

$ContactProperties = @(
    'displayName', 'mail', 'mailNickname', 'targetAddress', 'proxyAddresses',
    'legacyExchangeDN', 'msExchRecipientDisplayType', 'msExchRecipientTypeDetails',
    'msExchVersion', 'msExchHideFromAddressLists', 'showInAddressBook',
    'whenCreated', 'distinguishedName'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([string] $Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Get-ParentDn {
    param([string] $DistinguishedName)
    if ([string]::IsNullOrEmpty($DistinguishedName)) { return '' }
    $index = $DistinguishedName.IndexOf(',')
    if ($index -lt 0) { return $DistinguishedName }
    return $DistinguishedName.Substring($index + 1)
}

# Replaces the identifying part of a string while keeping its structure, so that a
# redacted output still shows the shape of an address or a legacyExchangeDN.
function Protect-Value {
    param(
        [string] $Value,
        [string] $Token
    )
    if (-not $Redact) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    # SMTP style: keep the prefix and the domain, mask the local part.
    if ($Value -match '^(?<prefix>[A-Za-z0-9]*:)?(?<local>[^@]+)@(?<domain>.+)$') {
        return ('{0}{1}@{2}' -f $Matches['prefix'], $Token, $Matches['domain'])
    }

    # X500 / legacyExchangeDN style: keep every component but the last cn.
    if ($Value -match '^/o=') {
        return ($Value -replace '(?<=cn=)[^/]+$', $Token)
    }

    return $Token
}

function ConvertTo-Reportable {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string[]] $Properties,
        [Parameter(Mandatory = $true)] [string] $Token
    )

    $result = [ordered]@{}
    foreach ($name in $Properties) {
        $raw = $null
        if ($Object.PSObject.Properties.Name -contains $name) { $raw = $Object.$name }

        if ($null -eq $raw) {
            $result[$name] = $null
            continue
        }

        switch ($name) {
            'distinguishedName' {
                # The container is what provisioning needs; the object's own name is not.
                $result['parentOU'] = Get-ParentDn -DistinguishedName ([string]$raw)
            }
            { $_ -in @('displayName', 'sAMAccountName', 'mailNickname', 'msExchArchiveName') } {
                # msExchArchiveName carries the mailbox display name and often the server
                # name, so it has to be masked with the rest of the identity fields.
                $result[$name] = if ($Redact) { $Token } else { [string]$raw }
            }
            { $_ -in @('userPrincipalName', 'mail', 'targetAddress', 'legacyExchangeDN') } {
                $result[$name] = Protect-Value -Value ([string]$raw) -Token $Token
            }
            'proxyAddresses' {
                $list = @()
                foreach ($entry in @($raw)) {
                    $list += (Protect-Value -Value ([string]$entry) -Token $Token)
                }
                $result[$name] = $list
            }
            { $_ -in @('authOrig', 'unauthOrig', 'dLMemSubmitPerms', 'dLMemRejectPerms',
                       'managedBy', 'msExchCoManagedByLink', 'homeMDB', 'homeMTA',
                       'msExchHomeServerName') } {
                # Distinguished names of other objects. Their presence matters, their
                # identity does not, so report how many there are and one sample shape.
                $values = @($raw)
                $result[$name] = if ($Redact) { ('<{0} value(s)>' -f $values.Count) } else { $values }
            }
            'whenCreated'  { $result[$name] = ([datetime]$raw).ToString('yyyy-MM-dd') }
            'whenChanged'  { $result[$name] = ([datetime]$raw).ToString('yyyy-MM-dd') }
            'msExchWhenMailboxCreated' { $result[$name] = ([datetime]$raw).ToString('yyyy-MM-dd') }
            'msExchMailboxGuid' { $result[$name] = '<present>' }
            'msExchArchiveGUID' { $result[$name] = '<present>' }
            default {
                if ($raw -is [System.Array] -or $raw -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
                    $result[$name] = @($raw | ForEach-Object { [string]$_ })
                }
                else {
                    $result[$name] = $raw
                }
            }
        }
    }

    return $result
}

# Groups objects by the combination of attribute values that determines their recipient
# type, so the output describes every shape in use rather than one arbitrary example.
function Get-PatternReport {
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Objects,
        [Parameter(Mandatory = $true)] [string[]] $KeyProperties,
        [Parameter(Mandatory = $true)] [string[]] $Properties,
        [Parameter(Mandatory = $true)] [string] $Label
    )

    $patterns = @()
    if ($Objects.Count -eq 0) { return $patterns }

    $groups = $Objects | Group-Object -Property {
        $parts = @()
        foreach ($key in $KeyProperties) {
            $value = $null
            if ($_.PSObject.Properties.Name -contains $key) { $value = $_.$key }
            if ($null -eq $value) { $value = '<null>' }
            $parts += ('{0}={1}' -f $key, $value)
        }
        $parts -join ' | '
    }

    $index = 0
    foreach ($group in ($groups | Sort-Object -Property Count -Descending)) {
        $index++
        $token = '{0}{1:D2}' -f $Label, $index

        $examples = @()
        $sample = @($group.Group | Select-Object -First $ExamplesPerPattern)
        $sampleIndex = 0
        foreach ($item in $sample) {
            $sampleIndex++
            $examples += (ConvertTo-Reportable -Object $item -Properties $Properties -Token ('{0}-{1}' -f $token, $sampleIndex))
        }

        # Which organisational units this pattern's objects live in, and how many in each.
        $containers = $group.Group |
            ForEach-Object { Get-ParentDn -DistinguishedName ([string]$_.distinguishedName) } |
            Group-Object |
            Sort-Object -Property Count -Descending |
            Select-Object -First 5 |
            ForEach-Object { [ordered]@{ ou = $_.Name; count = $_.Count } }

        $patterns += [ordered]@{
            pattern    = $group.Name
            count      = $group.Count
            containers = @($containers)
            examples   = @($examples)
        }
    }

    return $patterns
}

function Get-AddressDomainSummary {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Objects)

    $domains = @{}
    foreach ($item in $Objects) {
        $values = @()
        if ($item.PSObject.Properties.Name -contains 'targetAddress' -and $item.targetAddress) {
            $values += [string]$item.targetAddress
        }
        if ($item.PSObject.Properties.Name -contains 'proxyAddresses' -and $item.proxyAddresses) {
            $values += @($item.proxyAddresses | ForEach-Object { [string]$_ })
        }

        foreach ($value in $values) {
            if ($value -match '@(?<domain>[^@]+)$') {
                $domain = $Matches['domain'].ToLowerInvariant()
                $prefix = 'other'
                if ($value -cmatch '^SMTP:')      { $prefix = 'SMTP (primary)' }
                elseif ($value -cmatch '^smtp:')  { $prefix = 'smtp (secondary)' }
                elseif ($value -match '^[Ss][Mm][Tt][Pp]:') { $prefix = 'smtp' }

                $key = '{0}  {1}' -f $domain, $prefix
                if (-not $domains.ContainsKey($key)) { $domains[$key] = 0 }
                $domains[$key]++
            }
        }
    }

    return @(
        $domains.GetEnumerator() |
            Sort-Object -Property Value -Descending |
            ForEach-Object { [ordered]@{ domainAndUsage = $_.Key; count = $_.Value } }
    )
}

function Resolve-OutputFolder {
    param([string] $Requested)

    $candidates = @()
    if ($Requested) { $candidates += $Requested }
    $candidates += [Environment]::GetFolderPath('Desktop')
    $candidates += (Join-Path $env:ProgramData 'RecipientAttributeReference')
    $candidates += $env:TEMP

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try {
            if (-not (Test-Path -LiteralPath $candidate)) {
                New-Item -Path $candidate -ItemType Directory -Force | Out-Null
            }
            $folder = Join-Path $candidate ('RecipientAttributeReference_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
            return $folder
        }
        catch {
            continue
        }
    }

    throw 'Could not create an output folder in any of the candidate locations.'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host ('Recipient attribute reference {0} - read only' -f $script:Version) -ForegroundColor White
Write-Host ''

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host 'The ActiveDirectory PowerShell module is not available on this machine.' -ForegroundColor Red
    Write-Host 'Run this on a domain controller, or on a workstation with RSAT installed.' -ForegroundColor Red
    exit 1
}

if (-not $Server) {
    try {
        $Server = (Get-ADDomainController -Discover -Service ADWS -ErrorAction Stop).HostName | Select-Object -First 1
    }
    catch {
        Write-Host 'Could not discover a domain controller. Supply one with -Server.' -ForegroundColor Red
        exit 1
    }
}

$adCommon = @{ Server = $Server }
if ($SearchBase) { $adCommon['SearchBase'] = $SearchBase }

$domain = Get-ADDomain @adCommon
Write-Step ('Reading from {0} ({1})' -f $Server, $domain.DNSRoot)

# 1. Users that Exchange treats as remote (cloud) mailboxes.
Write-Step 'Collecting remote mailbox users'
$remoteUsers = @(Get-ADUser @adCommon -LDAPFilter '(msExchRemoteRecipientType=*)' -Properties $UserProperties)

# 2. Users that still hold an on-premises mailbox.
Write-Step 'Collecting on-premises mailbox users'
$onPremUsers = @(Get-ADUser @adCommon -LDAPFilter '(homeMDB=*)' -Properties $UserProperties)

# 3. Mail-enabled users that are neither of the above.
Write-Step 'Collecting mail enabled users'
$mailUsers = @(Get-ADUser @adCommon -LDAPFilter '(&(targetAddress=*)(!(msExchRemoteRecipientType=*))(!(homeMDB=*)))' -Properties $UserProperties)

# 4. Mail-enabled groups.
Write-Step 'Collecting mail enabled groups'
$mailGroups = @(Get-ADGroup @adCommon -LDAPFilter '(mailNickname=*)' -Properties $GroupProperties)

# 5. Mail contacts.
Write-Step 'Collecting mail contacts'
$mailContacts = @(Get-ADObject @adCommon -LDAPFilter '(&(objectClass=contact)(mailNickname=*))' -Properties $ContactProperties)

# 6. Organisation level facts that provisioning has to reproduce once the Exchange
#    cmdlets are gone. Each block is independent, so one unavailable section does not
#    stop the rest of the run.
Write-Step 'Collecting organisation configuration'

$environment = [ordered]@{}

try {
    $rootDse   = Get-ADRootDSE -Server $Server
    $configNc  = [string]$rootDse.configurationNamingContext
    $schemaNc  = [string]$rootDse.schemaNamingContext
    $exchBase  = "CN=Microsoft Exchange,CN=Services,$configNc"

    $org = @(Get-ADObject -Server $Server -SearchBase $exchBase -LDAPFilter '(objectClass=msExchOrganizationContainer)' -Properties name, legacyExchangeDN, whenCreated)
    $adminGroups = @(Get-ADObject -Server $Server -SearchBase $exchBase -LDAPFilter '(objectClass=msExchAdminGroup)' -Properties name, legacyExchangeDN)

    $environment['exchangeOrganisation'] = @(
        $org | ForEach-Object { [ordered]@{ name = [string]$_.name; legacyExchangeDN = [string]$_.legacyExchangeDN } }
    )
    $environment['administrativeGroups'] = @(
        $adminGroups | ForEach-Object { [ordered]@{ name = [string]$_.name; legacyExchangeDN = [string]$_.legacyExchangeDN } }
    )

    # Provisioning without Exchange has to generate legacyExchangeDN itself. This is the
    # prefix every new recipient's value must carry.
    if ($adminGroups.Count -gt 0 -and $adminGroups[0].legacyExchangeDN) {
        $environment['legacyExchangeDnTemplate'] = ('{0}/cn=Recipients/cn=<unique value>' -f [string]$adminGroups[0].legacyExchangeDN)
    }
}
catch {
    $environment['exchangeOrganisationError'] = $_.Exception.Message
}

try {
    # Email address policies are what stamps proxyAddresses today. Nothing applies them
    # once the server is gone, so the rewrite must reproduce these templates.
    $policies = @(Get-ADObject -Server $Server -SearchBase $exchBase -LDAPFilter '(objectClass=msExchRecipientPolicy)' -Properties name, gatewayProxy, msExchPolicyOrder, purportedSearch)
    $environment['emailAddressPolicies'] = @(
        $policies | ForEach-Object {
            [ordered]@{
                name              = [string]$_.name
                order             = [string]$_.msExchPolicyOrder
                addressTemplates  = @(@($_.gatewayProxy) | ForEach-Object { [string]$_ })
                recipientFilter   = [string]$_.purportedSearch
            }
        }
    )
}
catch {
    $environment['emailAddressPoliciesError'] = $_.Exception.Message
}

try {
    $accepted = @(Get-ADObject -Server $Server -SearchBase $exchBase -LDAPFilter '(objectClass=msExchAcceptedDomain)' -Properties *)
    $environment['acceptedDomains'] = @(
        $accepted | ForEach-Object {
            $entry = [ordered]@{ name = [string]$_.name }
            foreach ($prop in $_.PSObject.Properties) {
                if ($prop.Name -match 'domain' -and $prop.Value) {
                    $entry[$prop.Name] = ($prop.Value -join '; ')
                }
            }
            $entry
        }
    )
}
catch {
    $environment['acceptedDomainsError'] = $_.Exception.Message
}

try {
    $schemaVersion = Get-ADObject -Server $Server -SearchBase $schemaNc -LDAPFilter '(name=ms-Exch-Schema-Version-Pt)' -Properties rangeUpper
    $environment['exchangeSchemaVersion'] = if ($schemaVersion) { [string]$schemaVersion.rangeUpper } else { $null }
}
catch {
    $environment['exchangeSchemaVersionError'] = $_.Exception.Message
}

try {
    $forest = Get-ADForest -Server $Server
    $environment['upnSuffixes'] = @(@($forest.UPNSuffixes) + @($domain.DNSRoot) | Sort-Object -Unique)
}
catch {
    $environment['upnSuffixesError'] = $_.Exception.Message
}

try {
    # New-ADUser fails if the generated password does not satisfy the policy, which the
    # current automation relies on Exchange to accept on its behalf.
    $pwPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Server
    $environment['passwordPolicy'] = [ordered]@{
        minPasswordLength    = $pwPolicy.MinPasswordLength
        complexityEnabled    = $pwPolicy.ComplexityEnabled
        passwordHistoryCount = $pwPolicy.PasswordHistoryCount
        minPasswordAgeDays   = $pwPolicy.MinPasswordAge.TotalDays
        maxPasswordAgeDays   = $pwPolicy.MaxPasswordAge.TotalDays
    }
}
catch {
    $environment['passwordPolicyError'] = $_.Exception.Message
}

# 7. Directory synchronisation scope. Only available when this runs on the server that
#    holds Entra Connect; skipped silently everywhere else.
try {
    if (Get-Module -ListAvailable -Name ADSync) {
        Import-Module ADSync -ErrorAction Stop
        $environment['syncEngine'] = [ordered]@{
            connectors = @(
                Get-ADSyncConnector | ForEach-Object {
                    $scope = @()
                    try {
                        foreach ($partition in $_.Partitions) {
                            $scope += @($partition.ConnectorPartitionScope.ContainerInclusionList)
                        }
                    }
                    catch { }
                    [ordered]@{
                        name             = [string]$_.Name
                        type             = [string]$_.Type
                        includedContainers = @($scope | Where-Object { $_ } | Sort-Object -Unique)
                    }
                }
            )
            scheduler = $(
                try {
                    $s = Get-ADSyncScheduler
                    [ordered]@{
                        syncCycleEnabled     = $s.SyncCycleEnabled
                        allowedSyncCycleInterval = [string]$s.AllowedSyncCycleInterval
                        stagingModeEnabled   = $s.StagingModeEnabled
                    }
                }
                catch { $null }
            )
        }
    }
    else {
        $environment['syncEngine'] = 'ADSync module not present on this machine - run here only if this is the Entra Connect server'
    }
}
catch {
    $environment['syncEngineError'] = $_.Exception.Message
}

# 8. Named groups the automation depends on, supplied by the caller so that no
#    organisation specific name is built into this script.
if ($AdditionalGroup) {
    $environment['namedGroups'] = @(
        foreach ($groupName in $AdditionalGroup) {
            try {
                $found = Get-ADGroup -Server $Server -LDAPFilter ('(|(name={0})(sAMAccountName={0}))' -f $groupName) -Properties mailNickname, member
                if ($found) {
                    [ordered]@{
                        requested    = $groupName
                        found        = $true
                        groupScope   = [string]$found.GroupScope
                        groupCategory = [string]$found.GroupCategory
                        mailEnabled  = [bool]$found.mailNickname
                        memberCount  = @($found.member).Count
                        parentOU     = Get-ParentDn -DistinguishedName ([string]$found.DistinguishedName)
                    }
                }
                else {
                    [ordered]@{ requested = $groupName; found = $false }
                }
            }
            catch {
                [ordered]@{ requested = $groupName; found = $false; error = $_.Exception.Message }
            }
        }
    )
}

# 9. Conditions that would make a rewritten provisioning script fail on its first run.
$conflicts = [ordered]@{}
if (-not $SkipConflictCheck) {
    Write-Step 'Checking for duplicate addresses and aliases'
    try {
        $allMailObjects = @($remoteUsers) + @($onPremUsers) + @($mailUsers) + @($mailGroups) + @($mailContacts)

        $addressSeen = @{}
        foreach ($item in $allMailObjects) {
            if (-not $item.proxyAddresses) { continue }
            foreach ($entry in @($item.proxyAddresses)) {
                $address = ([string]$entry)
                if ($address -notmatch '^(?i)smtp:') { continue }
                $key = $address.Substring($address.IndexOf(':') + 1).ToLowerInvariant()
                if (-not $addressSeen.ContainsKey($key)) { $addressSeen[$key] = 0 }
                $addressSeen[$key]++
            }
        }
        $conflicts['duplicateSmtpAddresses'] = @(
            $addressSeen.GetEnumerator() | Where-Object { $_.Value -gt 1 } | ForEach-Object {
                [ordered]@{ address = (Protect-Value -Value $_.Key -Token 'duplicate'); count = $_.Value }
            }
        )

        $aliasSeen = @{}
        foreach ($item in $allMailObjects) {
            if (-not $item.mailNickname) { continue }
            $key = ([string]$item.mailNickname).ToLowerInvariant()
            if (-not $aliasSeen.ContainsKey($key)) { $aliasSeen[$key] = 0 }
            $aliasSeen[$key]++
        }
        $conflicts['duplicateAliases'] = @(
            $aliasSeen.GetEnumerator() | Where-Object { $_.Value -gt 1 } | ForEach-Object {
                [ordered]@{ alias = $(if ($Redact) { '<redacted>' } else { $_.Key }); count = $_.Value }
            }
        )

        $conflicts['remoteMailboxesMissingTargetAddress'] = @($remoteUsers | Where-Object { -not $_.targetAddress }).Count
        $conflicts['mailObjectsMissingLegacyExchangeDN'] = @($allMailObjects | Where-Object { -not $_.legacyExchangeDN }).Count
        $conflicts['mailEnabledGroupsNotUniversal'] = @($mailGroups | Where-Object { [string]$_.groupScope -ne 'Universal' }).Count
    }
    catch {
        $conflicts['error'] = $_.Exception.Message
    }
}

Write-Step 'Building patterns'

$report = [ordered]@{
    generatedUtc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    scriptVersion     = $script:Version
    redacted          = [bool]$Redact
    domainDnsRoot     = $domain.DNSRoot
    domainNetBIOS     = $domain.NetBIOSName
    forestMode        = [string]$domain.DomainMode
    readFromServer    = $Server
    searchBase        = if ($SearchBase) { $SearchBase } else { [string]$domain.DistinguishedName }

    counts = [ordered]@{
        remoteMailboxUsers  = $remoteUsers.Count
        onPremMailboxUsers  = $onPremUsers.Count
        otherMailEnabledUsers = $mailUsers.Count
        mailEnabledGroups   = $mailGroups.Count
        mailContacts        = $mailContacts.Count
    }

    addressDomains = Get-AddressDomainSummary -Objects (@($remoteUsers) + @($mailGroups) + @($mailUsers))

    environment = $environment

    conflicts = $conflicts

    remoteMailboxUserPatterns = Get-PatternReport -Objects $remoteUsers -Label 'RMB' -Properties $UserProperties -KeyProperties @(
        'msExchRemoteRecipientType', 'msExchRecipientDisplayType', 'msExchRecipientTypeDetails'
    )

    onPremMailboxUserPatterns = Get-PatternReport -Objects $onPremUsers -Label 'OPM' -Properties $UserProperties -KeyProperties @(
        'msExchRecipientDisplayType', 'msExchRecipientTypeDetails'
    )

    otherMailEnabledUserPatterns = Get-PatternReport -Objects $mailUsers -Label 'MEU' -Properties $UserProperties -KeyProperties @(
        'msExchRecipientDisplayType', 'msExchRecipientTypeDetails'
    )

    mailEnabledGroupPatterns = Get-PatternReport -Objects $mailGroups -Label 'GRP' -Properties $GroupProperties -KeyProperties @(
        'groupType', 'msExchRecipientDisplayType', 'msExchRecipientTypeDetails'
    )

    mailContactPatterns = Get-PatternReport -Objects $mailContacts -Label 'CON' -Properties $ContactProperties -KeyProperties @(
        'msExchRecipientDisplayType', 'msExchRecipientTypeDetails'
    )
}

# Human readable companion, so the output can be sanity checked before it is sent.
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('Recipient attribute reference')
$lines.Add('Generated (UTC): ' + $report.generatedUtc)
$lines.Add('Script version : ' + $report.scriptVersion)
$lines.Add('Domain         : ' + $report.domainDnsRoot)
$lines.Add('Redacted       : ' + $report.redacted)
$lines.Add('')
$lines.Add('Counts')
foreach ($entry in $report.counts.GetEnumerator()) {
    $lines.Add(('  {0,-22} {1}' -f $entry.Key, $entry.Value))
}
$lines.Add('')
$lines.Add('Address domains in use')
foreach ($entry in $report.addressDomains) {
    $lines.Add(('  {0,-6} {1}' -f $entry.count, $entry.domainAndUsage))
}

# Flattens the environment and conflict hashtables into readable lines without
# assuming which keys are present, since each block may have been skipped.
function Add-Section {
    param([string] $Title, $Data, [int] $Indent = 2)

    $pad = ' ' * $Indent
    if ($null -eq $Data) { return }

    if ($Data -is [string] -or $Data -is [int] -or $Data -is [bool] -or $Data -is [double]) {
        $lines.Add(('{0}{1}: {2}' -f $pad, $Title, $Data))
        return
    }

    $lines.Add(('{0}{1}' -f $pad, $Title))

    if ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) { Add-Section -Title $key -Data $Data[$key] -Indent ($Indent + 2) }
        return
    }

    if ($Data -is [System.Array]) {
        $itemIndex = 0
        foreach ($item in $Data) {
            $itemIndex++
            if ($item -is [System.Collections.IDictionary]) {
                $lines.Add(('{0}  [{1}]' -f $pad, $itemIndex))
                foreach ($key in $item.Keys) { Add-Section -Title $key -Data $item[$key] -Indent ($Indent + 4) }
            }
            else {
                $lines.Add(('{0}  {1}' -f $pad, $item))
            }
        }
        return
    }

    $lines.Add(('{0}  {1}' -f $pad, $Data))
}

$lines.Add('')
$lines.Add('=' * 76)
$lines.Add('Organisation configuration')
$lines.Add('=' * 76)
foreach ($key in $report.environment.Keys) {
    Add-Section -Title $key -Data $report.environment[$key]
}

$lines.Add('')
$lines.Add('=' * 76)
$lines.Add('Pre-flight checks')
$lines.Add('=' * 76)
if ($report.conflicts.Keys.Count -eq 0) {
    $lines.Add('  skipped')
}
else {
    foreach ($key in $report.conflicts.Keys) {
        Add-Section -Title $key -Data $report.conflicts[$key]
    }
}

$sections = @(
    @{ Title = 'Remote mailbox users';      Data = $report.remoteMailboxUserPatterns },
    @{ Title = 'On-premises mailbox users'; Data = $report.onPremMailboxUserPatterns },
    @{ Title = 'Other mail enabled users';  Data = $report.otherMailEnabledUserPatterns },
    @{ Title = 'Mail enabled groups';       Data = $report.mailEnabledGroupPatterns },
    @{ Title = 'Mail contacts';             Data = $report.mailContactPatterns }
)

foreach ($section in $sections) {
    $lines.Add('')
    $lines.Add('=' * 76)
    $lines.Add($section.Title)
    $lines.Add('=' * 76)
    if (@($section.Data).Count -eq 0) {
        $lines.Add('  none found')
        continue
    }
    foreach ($pattern in $section.Data) {
        $lines.Add('')
        $lines.Add(('  {0} object(s): {1}' -f $pattern.count, $pattern.pattern))
        foreach ($container in $pattern.containers) {
            $lines.Add(('    in {0}  ({1})' -f $container.ou, $container.count))
        }
        foreach ($example in $pattern.examples) {
            $lines.Add('    example:')
            foreach ($key in $example.Keys) {
                $value = $example[$key]
                if ($null -eq $value) { continue }
                if ($value -is [System.Array]) {
                    if (@($value).Count -eq 0) { continue }
                    $lines.Add(('      {0,-28} {1}' -f $key, (@($value) -join '; ')))
                }
                else {
                    $lines.Add(('      {0,-28} {1}' -f $key, $value))
                }
            }
        }
    }
}

# Collect any section that recorded an error, so a partial report says so up front
# rather than looking complete.
$sectionErrors = @()
foreach ($key in $report.environment.Keys) {
    if ($key -like '*Error') { $sectionErrors += ('{0}: {1}' -f $key, $report.environment[$key]) }
}
if ($report.conflicts.Contains('error')) { $sectionErrors += ('conflicts: {0}' -f $report.conflicts['error']) }

if ($Stdout) {
    # Used when the script is dispatched by an RMM tool: write nothing to disk, and put
    # the verdict first because the agent truncates long output from the end.
    Write-Output ('RESULT={0}' -f $(if ($sectionErrors.Count -eq 0) { 'OK' } else { 'PARTIAL' }))
    Write-Output ('VERSION={0}' -f $script:Version)
    Write-Output ('SECTION_ERRORS={0}' -f $sectionErrors.Count)
    foreach ($sectionError in $sectionErrors) { Write-Output ('  ! {0}' -f $sectionError) }
    foreach ($entry in $report.counts.GetEnumerator()) {
        Write-Output ('COUNT_{0}={1}' -f $entry.Key, $entry.Value)
    }
    Write-Output ''
    $lines | ForEach-Object { Write-Output $_ }
    Write-Output ''
    Write-Output 'END_OF_REPORT'
    return
}

$folder = Resolve-OutputFolder -Requested $OutputPath
$jsonPath = Join-Path $folder 'RecipientAttributeReference.json'
$textPath = Join-Path $folder 'RecipientAttributeReference.txt'

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
$lines | Out-File -FilePath $textPath -Encoding UTF8

Write-Host ''
Write-Host 'Done. No changes were made to the directory.' -ForegroundColor Green
Write-Host ('Output folder: {0}' -f $folder) -ForegroundColor Green
Write-Host ('  {0}' -f (Split-Path -Leaf $textPath)) -ForegroundColor Gray
Write-Host ('  {0}' -f (Split-Path -Leaf $jsonPath)) -ForegroundColor Gray
Write-Host ''
Write-Host 'Please review the .txt file before sending it back.' -ForegroundColor Yellow
Write-Host ''
if ($sectionErrors.Count -gt 0) {
    Write-Host ('{0} section(s) could not be collected:' -f $sectionErrors.Count) -ForegroundColor Yellow
    foreach ($sectionError in $sectionErrors) { Write-Host ('  {0}' -f $sectionError) -ForegroundColor Gray }
    Write-Host ''
}
