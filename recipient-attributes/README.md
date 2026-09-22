# Recipient attribute reference - what this script does and how to run it

**Script:** `Get-RecipientAttributeReference.ps1` (version 1.1.0)
**From:** BiTS Technology Group

## What this script is for

When an on-premises Exchange server is retired, cmdlets such as `New-RemoteMailbox` and
`New-DistributionGroup` go with it. The objects those cmdlets created are ordinary Active
Directory objects carrying a particular set of Exchange attributes, so provisioning can
continue by writing those attributes directly with the ActiveDirectory module.

Getting that right means knowing exactly which values the existing objects carry, rather
than assuming them. This script reports, for every distinct combination of Exchange
attribute values in the directory, how many objects carry it and one example in full. It
also collects the organisation level settings that provisioning has to reproduce once
Exchange is no longer there to apply them: the Exchange organisation and administrative
group names used to build `legacyExchangeDN`, the email address policy templates that
stamp `proxyAddresses`, the accepted domains, the available UPN suffixes and the password
policy any generated password has to satisfy.

## The script is read-only

- It uses only `Get-*` cmdlets from the ActiveDirectory module.
- It makes **no changes** to Active Directory, Exchange, Entra Connect, Windows or IIS.
- It does not contact the Exchange server and does not use remote PowerShell.
- It does not sign in to Microsoft 365 or any cloud service.
- It does not change execution policy. You run it with a one-off `-ExecutionPolicy Bypass`,
  which applies to that PowerShell process only.
- The only files it writes are its own two output files, in a folder it creates.

## Where to run it

Any domain-joined machine with the ActiveDirectory PowerShell module, which means a domain
controller, or a workstation or server with RSAT installed. It does **not** need to run on
the Exchange server.

If you run it on the server that holds Entra Connect, it also reports which organisational
units are in the synchronisation scope. That is useful but optional, and the script skips
that section silently everywhere else.

## How to run it

1. Copy `Get-RecipientAttributeReference.ps1` to the machine, for example `C:\Temp`.
2. Open PowerShell and run:

   ```
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Get-RecipientAttributeReference.ps1
   ```

3. It takes about a minute on a directory of a few thousand objects.

### Options

| Option | What it does |
|---|---|
| `-Redact` | Masks the local part of email addresses, account names and display names, keeping every Exchange attribute value and the directory structure intact |
| `-Server <name>` | Reads from a specific domain controller instead of an automatically discovered one |
| `-SearchBase <DN>` | Limits the search to one organisational unit |
| `-OutputPath <path>` | Writes the output somewhere other than the Desktop |
| `-AdditionalGroup <name>` | Also reports on named groups the automation depends on, such as a licensing group. Repeat or comma-separate for several |
| `-SkipConflictCheck` | Skips the duplicate address and alias check, the slowest part on a large directory |
| `-ExamplesPerPattern <n>` | Includes more than one example object per attribute pattern |

## What you get back

A folder named `RecipientAttributeReference_<date-time>` containing two files:

- `RecipientAttributeReference.txt` - the readable version. Review this before sending.
- `RecipientAttributeReference.json` - the same content for tooling.

## What is in the output

Counts and configuration, plus example objects. Specifically:

- For each recipient type found, the combination of `msExchRemoteRecipientType`,
  `msExchRecipientDisplayType` and `msExchRecipientTypeDetails` in use, how many objects
  carry it, and which organisational units they live in.
- One full example object per combination, showing every Exchange attribute it carries.
- The Exchange organisation and administrative group names, and the resulting
  `legacyExchangeDN` prefix.
- Email address policy templates, accepted domains, UPN suffixes, Exchange schema version
  and the default domain password policy.
- A short pre-flight list: duplicate SMTP addresses, duplicate aliases, mail-enabled groups
  that are not Universal, and objects missing `targetAddress` or `legacyExchangeDN`.

## What is not in the output

- No mailbox content, message content or message tracking data.
- No passwords, password hashes, keys or certificates.
- No group membership lists. Named groups are reported as a count only.
- With `-Redact`, no email addresses, account names or display names.

The output does contain directory structure, specifically organisational unit paths and
your email domains, because the provisioning rewrite needs to know where objects are
created and which address templates apply.
