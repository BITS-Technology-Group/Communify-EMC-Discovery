# Exchange management server discovery script - what it does and how to run it

**Scripts:** `Start-CommunifyDiscovery.ps1` (launcher) and `Invoke-CommunifyDiscovery.ps1` (version 1.1.5)
**From:** BiTS Technology Group

## What this script is for

This script gathers the facts needed to scope moving, replacing or retiring an on-premises
Exchange management server: the kind of server that remains after mailboxes have moved to
Exchange Online, kept on to manage recipients and to run onboarding and offboarding
automation.

It reports which Exchange version the server runs, whether any mailboxes or mail flow still
depend on it, how it is tied to Entra Connect and Active Directory, which scheduled scripts
use it, and how it is administered day to day (web admin centre, management console or
PowerShell).

That output is what distinguishes between three possible designs:

1. Move the Exchange management role onto a new Azure VM (needs a site-to-site VPN to
   Active Directory and Exchange Subscription Edition licensing).
2. Remove the server entirely and use Microsoft's standalone Exchange Management Tools.
   Only possible if no mailboxes or public folders remain on-premises, nothing relays mail
   through the server, no transport or journal rules are in use, and nothing depends on its
   web admin centre. It also requires every other Exchange server in the organisation to be
   removed.
3. Move recipient management to Exchange Online and retire the on-premises footprint.

## The script is read-only

- It makes **no changes** to Exchange, Active Directory, Entra Connect, Windows or IIS.
- It creates nothing in the directory, installs nothing, and does not change execution
  policy (you run it with a one-off `-ExecutionPolicy Bypass`, which applies to that
  PowerShell process only).
- It does not sign in to Microsoft 365 or any cloud service.
- The only files it writes are its own output files, in a folder it creates.
- Network activity is limited to:
  - LDAP reads of your Active Directory (the same thing every domain-joined machine does);
  - if the Exchange cmdlets cannot be loaded any other way, a Windows Remote Management
    (WinRM, Kerberos) session to the `/PowerShell` virtual directory **on the same server**,
    which is how the Exchange Management Shell itself works, closed when the script ends;
  - unless `-SkipNetworkTests` is given: a short set of TCP connection tests to your domain
    controller and to a fixed list of Microsoft endpoints, four ICMP pings to the domain
    controller, the DNS lookups needed for those tests, and a 2-second TCP port 135 probe to
    each server that hosts a mailbox database (so that database size and mounted state are
    only requested from servers that are actually online). See "Network tests" below.

For the technically minded: every collection call is a `Get-*` cmdlet, registry read,
WMI/CIM read, event-log read, file-metadata read or LDAP read. The handful of non-`Get` verbs
in the file are listed in the script's own `.NOTES` block with the reason for each; they load
cmdlets into the running PowerShell session (snap-ins, modules, an implicit remoting session),
close that session again, or write the output files. One of them,
`Set-ADServerSettings -ViewEntireForest $true`, sounds like a change but only widens the
recipient scope of that PowerShell session so that counts cover the whole forest; it writes
nothing.

## Time limit and partial output

The run is bounded by `-MaxMinutes` (default 20). Sections that would start after the deadline
are skipped and recorded as `SKIPPED_DEADLINE`; long enumerations (recipient counts, message
tracking, script scanning) stop early and say so with a truncation flag. `discovery.json` is
rewritten after every section, so a run that is interrupted (Ctrl-C, a management-agent
timeout) still leaves the data collected so far on disk. If a section was skipped, re-run with
a larger value, for example `-MaxMinutes 60`.

## What it collects

Everything is organised into lettered sections that match the report:

| Section | What is collected |
|---|---|
| A. Run metadata | Script version, timestamps, PowerShell and OS version, whether the process was elevated, 64-bit and domain-joined, which Exchange cmdlet-loading method worked, whether the deadline was reached, which sections failed or were skipped. |
| B. Host sizing | CPU, RAM, disk volumes (size and free space only), virtualisation platform, OS install date, uptime, .NET Framework version, PowerShell configuration, the account the script ran as (hashed). |
| C. Exchange footprint | Exchange version and build (from the registry, `ExSetup.exe` and Active Directory, so it works even without the Exchange tools), every Exchange server in the organisation with roles, version and site, the oldest and newest server version in the organisation, whether this host is a management-tools-only install (with the evidence used), local Exchange services, certificate inventory (subject, issuer, expiry, bound services, first 8 characters of the thumbprint; only server-authentication certificates), virtual directory URLs, RBAC role group names and member **counts**, mailbox database names, hosting server, replication type, mounted state and size. |
| C. Management interface evidence | How the server is actually administered, measured rather than guessed: which console files are present (the 2010 MMC console, the 2013+ Toolbox, the web admin centre application files); cmdlet **names** and counts from the `MSExchange Management` event log; **counts** of web admin centre, Outlook Web App and remote PowerShell requests in the newest IIS log files, with Exchange's own health-probe traffic excluded and the `clientApplication` token of PowerShell connections grouped (this is how the Management Shell identifies itself); activity dates of Exchange's own logging folders; whether the account running the script has an Exchange console in its MMC recent-file list (yes/no). The version-inferred guess is reported separately. |
| D. Non-recipient workloads | Receive and send connectors (names, bindings, IP ranges, permission groups, whether anonymous relay is allowed), message tracking **aggregate counts** by day, event type, source and connector, with SMTP receive events counted separately for default and custom connectors, transport agents, transport rule and journal rule **counts**, accepted and remote domains, IIS sites and applications, installed Windows roles, and installed programs that relate to mail flow, mail security, signatures, archiving or the Exchange/Entra footprint (a short list, not a software inventory). |
| E. Recipient inventory | **Counts only** of mailboxes by type (user, shared, room, equipment), system and arbitration mailboxes, remote (cloud) mailboxes, mail users, mail contacts, distribution groups, dynamic groups, mail-enabled public folders, top-level public folder count, address lists and e-mail address policies. The on-premises user mailbox count is reported prominently because it must be zero for option 2. |
| F. Hybrid configuration | Hybrid configuration features and servers, whether the Hybrid Configuration Wizard and Hybrid Agent are present, organisation relationships, federation trust, OAuth (auth servers, partner applications, intra-organisation connectors), migration endpoint count and type, the `*.mail.onmicrosoft.com` coexistence domain. |
| G. Entra Connect | Whether Entra Connect (Azure AD Connect) is installed on this machine and, if not, which server runs it (from the description of the sync service account in AD); version, service state, staging mode, scheduler settings, last sync events, sign-in method indicators, Exchange hybrid writeback and other optional features, connector names and OU-filter **counts**. |
| H. Active Directory | Forest and domain functional levels, domain list, site count, the AD site this computer is in with its subnets, domain controller inventory (name, domain, site, IP address for the local site, OS, global catalog, read-only), FSMO role holders, AD and Exchange schema versions, subnet count, trusts (read from this domain's own trust objects; no trust partner is contacted), DNS servers used by this host. |
| I. Automations | Scheduled tasks outside the `\Microsoft\` folder (state, last result, triggers, run-as account hashed, and **derived** facts about each action: the program that runs, the length of the argument string, whether the arguments contain a password-style switch, an encoded command or an execution-policy bypass, and the script files referenced, with folder and file names hashed), a whitelist of purpose keywords found in each task's name and description (for example "offboard", "mailbox", "licence"), scripts found in common script folders and referenced by tasks (protected path, size, last modified, a fingerprint of which Exchange / Graph / Azure AD / MSOnline / Active Directory cmdlets they call, and yes/no flags such as "contains a hard-coded credential pattern" or "loads a stored credential with Import-Clixml"), installed PowerShell modules relevant to identity and mail, services running under custom accounts, automation/RMM/ITSM products present. Every cap that could truncate this list sets a flag in the output. |
| J. Network | IP configuration, routes to private ranges, MTU, VPN/RRAS presence, machine-wide (WinHTTP) proxy settings, firewall profile state, TCP connectivity tests to your domain controller and a small fixed list of Microsoft endpoints, latency to the domain controller. |
| K. Licensing signals | Exchange edition, product ID, trial status, whether a hybrid (free) key is likely in use, the version span of the organisation, and Exchange Subscription Edition readiness indicators. |
| Summary | The at-a-glance feasibility read: Exchange version (local host and oldest server in the organisation), on-premises mailbox count, whether the server is an SMTP relay (or "unknown" when the evidence could not be read), how it is administered, whether Entra Connect is on the box, how many automation scripts were found, transport and journal rule counts, and the blockers detected for each option. |

## What it does NOT collect

The script never collects:

- mailbox names, display names, user principal names or e-mail addresses;
- group membership lists or user lists (only counts);
- message subjects, message bodies, or sender and recipient addresses (message tracking is
  read only for aggregate counts and only the timestamp, event type, source and connector
  fields are ever touched);
- the contents of any script or file (scripts are read to detect which cmdlets they call,
  but no line of any file is written to the output);
- the text of any scheduled task's name, folder path, description or command-line arguments
  (only hashes, lengths, folder depth, yes/no pattern flags and whitelisted keywords are kept);
- the names of script files or custom folders (hashed; only generic folder names such as
  `Scripts`, `Program Files` or `Windows` and the file extension are kept, plus a purpose
  prefix such as `Offboard-*.ps1` when the file name starts with a recognised verb);
- credential values, connection strings, secrets or private keys;
- full certificate thumbprints (only the first 8 characters), or certificates that are not
  server-authentication certificates (personal, S/MIME and code-signing certificates in the
  machine store are skipped);
- the text of any error message. When something fails, the report records a reason code
  (`AccessDenied`, `NotFound`, `Timeout`, `CmdletMissing`, ...) and a hash of the message,
  never the message itself, because Exchange and AD error text often contains object names;
- transport rule names, file shares, listening ports, the operator's browser proxy settings,
  volume labels, TLS registry settings, Windows Update history, page files or pending-reboot
  state;
- the Entra Connect sync account's password or connection settings (connector connectivity
  parameters are never read).

### How names are protected

Where an account name must be recorded (the account a service or scheduled task runs as,
the author of a scheduled task, the account the script ran as, the sync service account found
in AD), it is replaced by a one-way hash of the form `id:a1b2c3d4e5f6`. The hash is computed
with a 32-byte random salt that the script generates when it starts and never writes anywhere.
That means:

- within one report, the same account always gets the same hash, so BiTS can tell that two
  tasks run as the same account;
- the account name cannot be recovered from the hash, and cannot be confirmed by hashing a
  list of candidate names, because the salt is discarded when the script ends;
- the same account gets a different hash in a different run.

The same hashing is applied to task names and paths, script file names, custom folder names,
internal certificate-authority names, and error messages.

### What is recorded in clear

The following are organisation data rather than personal data and are collected in clear
**by default** because we need them to design the VPN and the server:

- server hostnames, Active Directory domain and forest names, the Exchange organisation name,
  accepted domains, AD site names, the public hostnames in your Exchange URLs;
- custom names you have given to receive/send connectors, IIS sites and applications,
  application pools, RBAC role groups, management scopes, databases, availability groups,
  organisation relationships, migration endpoints and VPN connections;
- the names of well-known public certificate authorities (DigiCert, Let's Encrypt, ...).

If your security team prefers, run with `-RedactHostnames` and every item in that list is
hashed as well. Note that the default names Exchange creates (`Default Frontend SERVER`,
`Client Proxy SERVER`, `Default Web Site`, `MSExchange...` application pools) embed the server
name; under `-RedactHostnames` only the server token inside them is hashed.

The following are always in clear in both modes because they carry no personal data and are
needed for the design: internal IP addresses and subnet ranges, Exchange build numbers,
Windows and product versions, cmdlet names, product names, Microsoft's own default object
names, well-known accounts (`SYSTEM`, `NT AUTHORITY\...`), and generic folder names.

## Prerequisites

- Copy **both** files, `Start-CommunifyDiscovery.ps1` and `Invoke-CommunifyDiscovery.ps1`,
  to the same folder on the server.
- Run it **on the Exchange management server** (the machine you use to manage Exchange).
  It will also produce a useful, reduced report from any other domain-joined Windows
  machine, reading Exchange configuration directly from Active Directory.
- Windows PowerShell 3.0 or later is required by the discovery script; the launcher takes
  care of finding it. The Exchange 2010 Management Shell shortcut starts PowerShell in
  version 2.0 mode, and the launcher detects that and starts the right engine for you. If the
  server only has PowerShell 2.0 installed (Windows Server 2008 R2 without the Windows
  Management Framework 3.0 update), the launcher prints one message telling you to run it
  from another domain-joined Windows 10/11 or Server 2016+ machine instead.
- Run it **as an administrator** (right-click, "Run as administrator") so that it can read
  all scheduled tasks, the IIS logs and Entra Connect settings.
- Run it as an account that is a member of the Exchange **View-Only Organization
  Management** role group (or Organization Management). Without that, the Exchange sections
  will record `AccessDenied` reason codes and the script will fall back to the reduced AD-only
  view, which still gives us the version and mailbox counts but not connector detail, and the
  SMTP relay answer will be reported as "unknown" rather than guessed.
- If Entra Connect is on the same server, the account should also be in the local
  `ADSyncAdmins` group (administrators normally are).
- No internet access is required. The optional network tests simply report "unreachable"
  if there is none.

Typical run time is two to ten minutes. Message tracking summarisation on a busy server can
add a few minutes; it is capped at 250,000 events and 14 days. The whole run stops at
`-MaxMinutes` (default 20) and writes what it has.

## How to run it

1. Copy `Start-CommunifyDiscovery.ps1` and `Invoke-CommunifyDiscovery.ps1` to the server,
   for example to `C:\Temp`.
2. Open **Windows PowerShell as administrator**. The Exchange Management Shell is fine too;
   the launcher handles both.
3. Run:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1
   ```

   Useful variations (every parameter is passed through to the discovery script):

   ```powershell
   # Write the output somewhere other than the Desktop
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1 -OutputPath D:\Temp

   # Hardened mode: also hash server, domain, site and custom object names
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1 -RedactHostnames

   # No outbound connection tests; summarise 14 days of message tracking instead of 7
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1 -SkipNetworkTests -MessageTrackingDays 14

   # Allow up to an hour on a large or slow environment
   powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Start-CommunifyDiscovery.ps1 -MaxMinutes 60
   ```

   `-ExecutionPolicy Bypass` affects only that PowerShell process; the machine's execution
   policy is not changed.

4. Watch the console. Each section reports OK, WARN, FAIL or SKIP as it completes. A WARN or
   FAIL in one section never stops the others; the reason code is written into the report.
5. When it finishes it prints the output folder. By default that is
   `%USERPROFILE%\Desktop\CommunifyDiscovery_<date-time>` (if the Desktop does not exist,
   for example when the script is run by a management agent as SYSTEM, it uses
   `%ProgramData%\CommunifyDiscovery` and then `%TEMP%`). Inside the files the folder path
   is recorded with the user-name segment hashed. The folder contains:

   | File | Purpose |
   |---|---|
   | `discovery-report.txt` | The complete, human-readable report, section by section. **Please read this before sending anything.** It is exactly what BiTS will receive. |
   | `discovery-summary.txt` | One page: Exchange version, mailbox count, SMTP relay yes/no/unknown, how the server is administered, Entra Connect on this box yes/no, automation script count, blockers detected, section status. |
   | `discovery.json` | The same data as the report, in structured form, for BiTS to analyse. |

   A `.zip` of the folder is created next to it when the `Compress-Archive` cmdlet is
   available (Windows Server 2012 R2 with WMF 5 and later).

6. Review `discovery-report.txt`. If there is anything you are not comfortable sending,
   delete that line from all three files (or re-run with `-RedactHostnames`) and tell us
   which section you edited so we know to ask about it on the call.
7. Send the zip (or the folder) to your BiTS contact.

### Network tests

Unless `-SkipNetworkTests` is given, the script attempts a plain TCP connection (no sign-in,
no data sent, closed immediately) to:

- your domain controller on ports 53, 88, 135, 389, 445, 636, 3268, 3269 and 5985;
- `login.microsoftonline.com`, `graph.microsoft.com`, `outlook.office365.com` and
  `management.azure.com` on port 443, `outlook.office365.com` on port 25,
  `smtp.office365.com` on port 587 and `www.microsoft.com` on port 80;
- port 135 on each server that hosts a mailbox database (2-second probe, so that database
  status is only requested from servers that are online).

It also sends four ICMP pings to the domain controller to measure latency, and performs the
DNS lookups those tests need. Each test has a 2 to 4 second timeout, so the whole set takes
well under a minute even with no internet.

### Running it through a management agent (optional)

The `-CompactOutput` switch is intended for RMM tools that capture the console and truncate
long output. It changes nothing about what is collected or written to the files; it only
replaces the console progress with a short block of `key=value` lines, one status line per
section, a `VERDICT=` line and a final `TRUNCATION_GUARD=END_OF_OUTPUT` line so the operator
can see the output arrived intact. Blockers are always kept in that block. Nothing is written
to the error stream, so agents that treat error output as failure will not misreport the run.
If the agent runs 32-bit PowerShell, the launcher restarts the 64-bit engine automatically.
You do not need this switch when running the script by hand.

## Things the script cannot see - please answer these separately

The script runs inside your network and cannot see the site edge. When you send the output,
please also tell us (or send us your network provider's details for):

1. Your public IP address(es) and who provides the internet circuit, with its bandwidth up
   and down.
2. The make and model of the firewall or VPN appliance at the site (and whether it already
   terminates any site-to-site VPNs, for example to another office or to Azure).
3. Who currently administers Exchange, and whether they use the web admin centre, the
   management console or PowerShell (the script measures this, but a sentence from you
   confirms it).
4. Whether any other server at the site runs Exchange, and whether any application or
   device (multifunction printers, scanners, line-of-business systems) sends e-mail through
   the Exchange server.
5. Whether the server is backed up, and by what.

## Questions

If anything in this document or in the report is unclear, or you would prefer to run the
script together with a BiTS engineer on a screen-share, contact your BiTS account manager.
