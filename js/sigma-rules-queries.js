// ═══════════════════════════════════════════════════════════════════════
// SIEM Query Patch — Adds Splunk SPL + QRadar AQL to legacy rules (Parts 1-4)
// Loaded AFTER sigma-rules-part8.js, patches queries into SIGMA_RULES array
// ═══════════════════════════════════════════════════════════════════════

const SIEM_QUERY_PATCH = {

// ═══ PART 1: SR-0001 to SR-0025 ═══

'SR-0001': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.EXE$")
  AND match(Image,"(?i)(cmd|powershell|wscript|cscript|mshta|certutil)\\.exe$")
| stats count values(Image) as child_procs values(CommandLine) as commands by ComputerName, User, ParentImage, _time
| table _time, ComputerName, User, ParentImage, child_procs, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path" as parent_process,
  Filename as child_process,
  COUNT(*) as exec_count
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ("Parent Process Path" ILIKE '%WINWORD%' OR "Parent Process Path" ILIKE '%EXCEL%' OR "Parent Process Path" ILIKE '%OUTLOOK%')
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe' OR Filename ILIKE '%wscript.exe' OR Filename ILIKE '%mshta.exe')
GROUP BY sourceip, username, "Parent Process Path", Filename
ORDER BY exec_count DESC
LAST 24 HOURS`
},

'SR-0002': {
  splunkQuery: `index=proxy sourcetype=proxy action=allowed
| where match(url,"(?i)(login|signin|account|verify|secure|update|confirm)") AND match(url,"(?i)(\\.(tk|ml|ga|cf|xyz|top|buzz|gq|work))$")
| stats count dc(src_ip) as unique_users values(src_ip) as users by url, dest, _time
| where count > 3
| table _time, url, dest, unique_users, users, count`,
  qradarQuery: `SELECT sourceip, url, destinationip,
  COUNT(*) as click_count,
  COUNT(DISTINCT sourceip) as unique_users
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Web'
  AND (url ILIKE '%login%' OR url ILIKE '%signin%' OR url ILIKE '%verify%' OR url ILIKE '%secure%')
  AND (url ILIKE '%.tk%' OR url ILIKE '%.xyz%' OR url ILIKE '%.top%' OR url ILIKE '%.ml%')
GROUP BY sourceip, url, destinationip
HAVING COUNT(*) > 3
ORDER BY click_count DESC
LAST 24 HOURS`
},

'SR-0003': {
  splunkQuery: `index=waf OR index=proxy sourcetype=waf*
| where match(uri,"(?i)(\\.\\./|%2e%2e|select.*from|union.*select|<script|exec\\(|eval\\(|cmd=|/etc/passwd|/bin/sh)")
| stats count dc(src_ip) as unique_attackers values(uri) as attack_uris by dest, http_method, status, _time
| where count > 10
| table _time, dest, http_method, status, unique_attackers, count, attack_uris`,
  qradarQuery: `SELECT sourceip, destinationip, url,
  COUNT(*) as attack_count
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Application'
  AND (url ILIKE '%../%' OR url ILIKE '%select%from%' OR url ILIKE '%union%select%'
    OR url ILIKE '%<script%' OR url ILIKE '%/etc/passwd%')
GROUP BY sourceip, destinationip, url
HAVING COUNT(*) > 10
ORDER BY attack_count DESC
LAST 24 HOURS`
},

'SR-0004': {
  splunkQuery: `index=vpn OR index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| bin _time span=30m
| stats count as failures dc(TargetUserName) as unique_users values(TargetUserName) as users by IpAddress, _time
| where failures > 10
| sort - failures
| table _time, IpAddress, failures, unique_users, users`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as failed_logins,
  COUNT(DISTINCT username) as unique_users
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Authentication%Failure%'
  AND (LOGSOURCETYPENAME(devicetype) ILIKE '%VPN%' OR EventID = 4625)
GROUP BY sourceip
HAVING COUNT(*) > 10
ORDER BY failed_logins DESC
LAST 4 HOURS`
},

'SR-0005': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 (LogonType=2 OR LogonType=10)
| eval hour=strftime(_time,"%H")
| where (hour > 20 OR hour < 6) AND NOT match(TargetUserName,"(SYSTEM|\\$$|-)")
| stats count dc(ComputerName) as systems values(ComputerName) as targets by TargetUserName, IpAddress, _time
| table _time, TargetUserName, IpAddress, systems, targets, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as offhours_logins
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Success%'
  AND (EXTRACT(HOUR FROM starttime) > 20 OR EXTRACT(HOUR FROM starttime) < 6)
  AND username NOT IN ('SYSTEM', '-', 'ANONYMOUS LOGON')
GROUP BY username, sourceip, destinationip
HAVING COUNT(*) > 0
ORDER BY offhours_logins DESC
LAST 24 HOURS`
},

'SR-0006': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Security EventCode=4688)
| where match(Image,"(?i)(powershell|pwsh)\\.exe$")
  AND match(CommandLine,"(?i)(-enc\\s|-EncodedCommand|-e\\s+[A-Za-z0-9+/=]{20,})")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username, Command,
  COUNT(*) as encoded_ps
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%powershell%' OR Filename ILIKE '%pwsh%')
  AND (Command ILIKE '%-enc %' OR Command ILIKE '%-EncodedCommand%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0007': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\cmd\\.exe$")
  AND match(CommandLine,"(?i)(whoami|net\\s+(user|localgroup|group)|ipconfig|systeminfo|tasklist|reg\\s+query|wmic|nltest)")
| bin _time span=5m
| stats count dc(CommandLine) as unique_cmds values(CommandLine) as commands by ComputerName, User, _time
| where unique_cmds > 3
| table _time, ComputerName, User, unique_cmds, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  COUNT(*) as cmd_count,
  COUNT(DISTINCT Command) as unique_commands
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%cmd.exe'
  AND (Command ILIKE '%whoami%' OR Command ILIKE '%net user%' OR Command ILIKE '%ipconfig%'
    OR Command ILIKE '%systeminfo%' OR Command ILIKE '%tasklist%')
GROUP BY sourceip, username
HAVING COUNT(DISTINCT Command) > 3
ORDER BY cmd_count DESC
LAST 4 HOURS`
},

'SR-0008': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)WmiPrvSE\\.exe$")
  AND match(Image,"(?i)(cmd|powershell|mshta|rundll32)\\.exe$")
| stats count values(Image) as processes values(CommandLine) as commands by ComputerName, User, _time
| table _time, ComputerName, User, processes, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as wmi_exec
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND "Parent Process Path" ILIKE '%WmiPrvSE.exe'
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe' OR Filename ILIKE '%mshta.exe')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0009': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4698
| where match(TaskContent,"(?i)(powershell|cmd\\.exe|http|base64|\\\\Temp\\\\|AppData)")
| stats count values(TaskName) as tasks by SubjectUserName, ComputerName, _time
| table _time, SubjectUserName, ComputerName, tasks, count`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as task_events
FROM events
WHERE EventID = 4698
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 7 DAYS`
},

'SR-0010': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\.(pdf|doc|docx|jpg|png)\\.exe$")
  OR match(Image,"(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\).*\\.exe$")
| where NOT match(Image,"(?i)(Microsoft|Windows|Program Files)")
| table _time, ComputerName, User, Image, CommandLine, Hashes`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as suspicious_exec
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%.pdf.exe' OR Filename ILIKE '%.doc.exe' OR Filename ILIKE '%.jpg.exe'
    OR (Filename ILIKE '%\\Temp\\%.exe' AND Filename NOT ILIKE '%Microsoft%'))
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0011': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=13
| where match(TargetObject,"(?i)\\\\(Run|RunOnce)\\\\")
  AND NOT match(Details,"(?i)(Microsoft|Windows|Program Files)")
| table _time, ComputerName, User, TargetObject, Details`,
  qradarQuery: `SELECT sourceip, username,
  "Registry Key" as reg_key,
  "Registry Value" as reg_value,
  COUNT(*) as reg_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Registry%'
  AND ("Registry Key" ILIKE '%\\Run\\%' OR "Registry Key" ILIKE '%\\RunOnce\\%')
GROUP BY sourceip, username, "Registry Key", "Registry Value"
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0012': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4720
| table _time, SubjectUserName, TargetUserName, ComputerName
| append [search index=wineventlog sourcetype=WinEventLog:Security EventCode=4732
| where match(TargetUserName,"Administrators")
| table _time, SubjectUserName, MemberName, ComputerName]`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as account_events
FROM events
WHERE EventID IN (4720, 4732, 4728)
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0013': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| where NOT match(ImagePath,"(?i)(Microsoft|Windows|Program Files)")
| stats count values(ImagePath) as paths by ServiceName, ComputerName, _time
| table _time, ComputerName, ServiceName, paths, count`,
  qradarQuery: `SELECT sourceip, "Service Name",
  QIDNAME(qid) as event_name,
  COUNT(*) as service_installs
FROM events
WHERE EventID = 7045
GROUP BY sourceip, "Service Name", qid
ORDER BY starttime DESC
LAST 7 DAYS`
},

'SR-0014': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval wmi_type=case(EventCode=19,"Filter",EventCode=20,"Consumer",EventCode=21,"Binding")
| stats count values(wmi_type) as components values(Name) as names by ComputerName, User, _time
| table _time, ComputerName, User, components, names, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as wmi_events
FROM events
WHERE QIDNAME(qid) ILIKE '%WMI%'
  AND (eventname ILIKE '%Consumer%' OR eventname ILIKE '%Filter%' OR eventname ILIKE '%Binding%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0015': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)\\\\(Startup|Start Menu\\\\Programs\\\\Startup)\\\\")
  AND match(TargetFilename,"(?i)\\.(exe|bat|cmd|vbs|js|lnk|ps1)$")
| table _time, ComputerName, User, TargetFilename, Image`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as startup_events
FROM events
WHERE QIDNAME(qid) ILIKE '%File Create%'
  AND (Filename ILIKE '%\\Startup\\%')
  AND (Filename ILIKE '%.exe' OR Filename ILIKE '%.bat' OR Filename ILIKE '%.lnk' OR Filename ILIKE '%.vbs')
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0016': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(eventvwr|mscfile|sdclt)")
  AND match(Image,"(?i)(cmd|powershell)\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as uac_bypass
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%eventvwr%' OR Command ILIKE '%mscfile%' OR Command ILIKE '%sdclt%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0017': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=8
| where NOT match(SourceImage,"(?i)(csrss|lsass|svchost|services|MsMpEng)\\.exe$")
| stats count values(TargetImage) as targets by ComputerName, SourceImage, SourceUser, _time
| table _time, ComputerName, SourceUser, SourceImage, targets, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as injection_events
FROM events
WHERE QIDNAME(qid) ILIKE '%CreateRemoteThread%'
  AND "Source Process" NOT ILIKE '%csrss.exe'
  AND "Source Process" NOT ILIKE '%svchost.exe'
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY injection_events DESC
LAST 24 HOURS`
},

'SR-0018': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(whoami\\s+/priv|SeDebugPrivilege|SeImpersonatePrivilege|incognito|token)")
  AND match(CommandLine,"(?i)(enable|impersonate|steal|delegate)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as token_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%whoami%priv%' OR Command ILIKE '%SeDebugPrivilege%'
    OR Command ILIKE '%incognito%' OR Command ILIKE '%token%impersonate%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0019': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=6
| where NOT match(ImageLoaded,"(?i)(Microsoft|Windows)")
  AND match(ImageLoaded,"(?i)\\.sys$")
| table _time, ComputerName, User, ImageLoaded, Hashes, Signed, Signature`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as driver_loads
FROM events
WHERE QIDNAME(qid) ILIKE '%Driver Load%'
  AND Filename NOT ILIKE '%Microsoft%'
  AND Filename NOT ILIKE '%Windows%'
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 7 DAYS`
},

'SR-0020': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:System EventCode=7036)
| where (match(CommandLine,"(?i)(net\\s+stop|sc\\s+(stop|config|delete))") AND match(CommandLine,"(?i)(WinDefend|MsMpSvc|Sense|SepMasterService|McAfeeFramework|avp)"))
  OR (match(ServiceName,"(?i)(WinDefend|MsMpSvc|Sense)") AND match(Message,"stopped"))
| table _time, ComputerName, User, CommandLine, ServiceName`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  Command,
  COUNT(*) as tamper_events
FROM events
WHERE (Command ILIKE '%net stop%WinDefend%' OR Command ILIKE '%sc stop%WinDefend%'
  OR Command ILIKE '%sc stop%Sense%' OR Command ILIKE '%sc delete%')
  OR (eventname ILIKE '%WinDefend%' AND eventname ILIKE '%stopped%')
GROUP BY sourceip, username, qid, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0021': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security EventCode=1102) OR (sourcetype=WinEventLog:System EventCode=104)
| eval log_type=case(EventCode=1102,"Security Log Cleared",EventCode=104,"System Log Cleared")
| table _time, ComputerName, SubjectUserName, log_type`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as log_clear_events
FROM events
WHERE EventID IN (1102, 104)
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0022': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(svchost|lsass|csrss|smss|services|explorer)\\.exe$")
  AND NOT match(Image,"(?i)C:\\\\Windows\\\\(System32|SysWOW64)\\\\")
| table _time, ComputerName, User, Image, CommandLine, Hashes`,
  qradarQuery: `SELECT sourceip, username,
  Filename, "File Path",
  COUNT(*) as masquerade_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%svchost.exe' OR Filename ILIKE '%lsass.exe' OR Filename ILIKE '%csrss.exe')
  AND "File Path" NOT ILIKE '%Windows\\System32%'
GROUP BY sourceip, username, Filename, "File Path"
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0023': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)rundll32\\.exe$")
  AND match(CommandLine,"(?i)(javascript:|http:|https:|\\\\Temp\\\\|\\\\AppData\\\\|,#|DllRegisterServer)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as rundll32_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%rundll32.exe'
  AND (Command ILIKE '%javascript:%' OR Command ILIKE '%http:%' OR Command ILIKE '%\\Temp\\%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0024': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=13
| where match(TargetObject,"(?i)(DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|EnableLUA)")
| table _time, ComputerName, User, TargetObject, Details`,
  qradarQuery: `SELECT sourceip, username,
  "Registry Key", "Registry Value",
  COUNT(*) as reg_defense_evasion
FROM events
WHERE QIDNAME(qid) ILIKE '%Registry%'
  AND ("Registry Key" ILIKE '%DisableAntiSpyware%' OR "Registry Key" ILIKE '%DisableRealtimeMonitoring%'
    OR "Registry Key" ILIKE '%EnableLUA%')
GROUP BY sourceip, username, "Registry Key", "Registry Value"
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0025': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104)
| where match(CommandLine,"(?i)(-enc\\s|-EncodedCommand|FromBase64String|\\[Convert\\]|\\[char\\]|replace.*replace|-join|iex)")
  OR match(ScriptBlockText,"(?i)(FromBase64|IO\\.Compression|Net\\.WebClient|Invoke-Expression)")
| table _time, ComputerName, User, CommandLine, ScriptBlockText`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as obfuscated_ps
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%powershell%' OR Filename ILIKE '%pwsh%')
  AND (Command ILIKE '%-enc %' OR Command ILIKE '%EncodedCommand%' OR Command ILIKE '%FromBase64%' OR Command ILIKE '%[char]%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

// ═══ PART 2: SR-0026 to SR-0055 ═══

'SR-0026': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| bin _time span=30m
| stats count as failures dc(TargetUserName) as unique_accounts values(TargetUserName) as accounts by IpAddress, _time
| where failures > 20 AND unique_accounts > 5
| sort - failures
| table _time, IpAddress, failures, unique_accounts, accounts`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as failed_logins,
  COUNT(DISTINCT username) as unique_accounts
FROM events
WHERE EventID = 4625
GROUP BY sourceip
HAVING COUNT(*) > 20 AND COUNT(DISTINCT username) > 5
ORDER BY failed_logins DESC
LAST 4 HOURS`
},

'SR-0027': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=10
| where match(TargetImage,"(?i)lsass\\.exe$")
  AND NOT match(SourceImage,"(?i)(MsMpEng|csrss|svchost|wininit)\\.exe$")
| table _time, ComputerName, SourceImage, SourceUser, GrantedAccess, CallTrace`,
  qradarQuery: `SELECT sourceip, username,
  "Source Process",
  COUNT(*) as lsass_access
FROM events
WHERE QIDNAME(qid) ILIKE '%Process Access%'
  AND "Target Process" ILIKE '%lsass.exe'
  AND "Source Process" NOT ILIKE '%MsMpEng%'
GROUP BY sourceip, username, "Source Process"
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0028': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName,"(krbtgt|\\$$)")
| bin _time span=30m
| stats dc(ServiceName) as unique_spns count by TargetUserName, IpAddress, _time
| where unique_spns > 3
| table _time, TargetUserName, IpAddress, unique_spns, count`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(DISTINCT "Service Name") as unique_spns,
  COUNT(*) as tgs_requests
FROM events
WHERE EventID = 4769
  AND "Encryption Type" = '0x17'
  AND "Service Name" NOT ILIKE '%$'
  AND "Service Name" <> 'krbtgt'
GROUP BY username, sourceip
HAVING COUNT(DISTINCT "Service Name") > 3
ORDER BY unique_spns DESC
LAST 4 HOURS`
},

'SR-0029': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
| where AccessMask="0x100"
  AND (match(Properties,"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") OR match(Properties,"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"))
  AND NOT match(SubjectUserName,"\\$$")
| table _time, SubjectUserName, SubjectDomainName, ComputerName`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as dcsync_events
FROM events
WHERE EventID = 4662
  AND username NOT ILIKE '%$'
GROUP BY username, sourceip, qid
HAVING COUNT(*) > 0
ORDER BY dcsync_events DESC
LAST 24 HOURS`
},

'SR-0030': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(Login Data|Web Data|cookies\\.sqlite|logins\\.json|key3\\.db|key4\\.db)")
  OR (match(Image,"(?i)\\\\(copy|xcopy|type|robocopy)\\.exe$") AND match(CommandLine,"(?i)(Chrome|Firefox|Edge)"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as browser_cred_access
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%Login Data%' OR Command ILIKE '%cookies.sqlite%' OR Command ILIKE '%logins.json%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0031': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4768
| where TicketEncryptionType="0x17" AND Status="0x0"
| bin _time span=1h
| stats dc(TargetUserName) as unique_users count by IpAddress, _time
| where unique_users > 5
| table _time, IpAddress, unique_users, count`,
  qradarQuery: `SELECT sourceip,
  COUNT(DISTINCT username) as unique_users,
  COUNT(*) as asrep_requests
FROM events
WHERE EventID = 4768
  AND "Encryption Type" = '0x17'
GROUP BY sourceip
HAVING COUNT(DISTINCT username) > 5
ORDER BY asrep_requests DESC
LAST 4 HOURS`
},

'SR-0032': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(net\\s+user\\s+/domain|Get-ADUser|dsquery|ldapsearch|adfind|bloodhound|sharphound)")
| stats count values(CommandLine) as commands by ComputerName, User, _time
| table _time, ComputerName, User, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as enum_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%net user%/domain%' OR Command ILIKE '%Get-ADUser%'
    OR Command ILIKE '%bloodhound%' OR Command ILIKE '%sharphound%' OR Command ILIKE '%adfind%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0033': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(systeminfo|hostname|whoami|ipconfig|net\\s+config|nltest|gpresult|set\\s)")
| bin _time span=5m
| stats dc(CommandLine) as unique_cmds count by ComputerName, User, _time
| where unique_cmds > 4
| table _time, ComputerName, User, unique_cmds, count`,
  qradarQuery: `SELECT sourceip, username,
  COUNT(DISTINCT Command) as unique_commands,
  COUNT(*) as total_commands
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%systeminfo%' OR Command ILIKE '%whoami%' OR Command ILIKE '%ipconfig%'
    OR Command ILIKE '%hostname%' OR Command ILIKE '%gpresult%')
GROUP BY sourceip, username
HAVING COUNT(DISTINCT Command) > 4
ORDER BY total_commands DESC
LAST 4 HOURS`
},

'SR-0034': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(nmap|masscan|ping\\s+-t|arp\\s+-a|Test-NetConnection|portscan|Advanced IP Scanner)")
  OR (match(Image,"(?i)\\\\(nmap|masscan)\\.exe$"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as scan_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%nmap%' OR Command ILIKE '%masscan%' OR Command ILIKE '%portscan%'
    OR Filename ILIKE '%nmap.exe' OR Command ILIKE '%Test-NetConnection%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0035': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(net\\s+group|net\\s+localgroup|Get-ADGroup|Get-LocalGroupMember|whoami\\s+/groups)")
| stats count values(CommandLine) as commands by ComputerName, User, _time
| table _time, ComputerName, User, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as group_enum
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%net group%' OR Command ILIKE '%net localgroup%' OR Command ILIKE '%Get-ADGroup%' OR Command ILIKE '%whoami%groups%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0036': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=10
| where NOT match(IpAddress,"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")
  OR IpAddress="0.0.0.0"
| stats count dc(ComputerName) as systems values(ComputerName) as targets by TargetUserName, IpAddress, _time
| table _time, TargetUserName, IpAddress, systems, targets, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as rdp_logins
FROM events
WHERE EventID = 4624
  AND "Logon Type" = 10
GROUP BY username, sourceip, destinationip
ORDER BY rdp_logins DESC
LAST 24 HOURS`
},

'SR-0037': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=5140
| where match(ShareName,"(?i)(\\$|ADMIN|C\\$|IPC\\$)")
| stats count dc(ShareName) as unique_shares values(ShareName) as shares by SubjectUserName, IpAddress, _time
| table _time, SubjectUserName, IpAddress, unique_shares, shares, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as share_access,
  COUNT(DISTINCT "Share Name") as unique_shares
FROM events
WHERE EventID = 5140
  AND ("Share Name" ILIKE '%$%' OR "Share Name" ILIKE '%ADMIN%')
GROUP BY username, sourceip, destinationip
ORDER BY share_access DESC
LAST 24 HOURS`
},

'SR-0038': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=3
| where match(AuthenticationPackageName,"Negotiate") AND match(ProcessName,"(?i)wsmprovhost")
| stats count dc(ComputerName) as systems by TargetUserName, IpAddress, _time
| table _time, TargetUserName, IpAddress, systems, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as winrm_sessions
FROM events
WHERE EventID = 4624
  AND eventname ILIKE '%WinRM%'
GROUP BY username, sourceip, destinationip
ORDER BY winrm_sessions DESC
LAST 24 HOURS`
},

'SR-0039': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=9
| where match(AuthenticationPackageName,"(?i)NTLM") AND LogonProcessName="seclogo"
| stats count dc(ComputerName) as systems by TargetUserName, IpAddress, _time
| table _time, TargetUserName, IpAddress, systems, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as pth_indicators
FROM events
WHERE EventID = 4624
  AND "Logon Type" = 9
  AND "Authentication Package" ILIKE '%NTLM%'
GROUP BY username, sourceip, destinationip
ORDER BY pth_indicators DESC
LAST 24 HOURS`
},

'SR-0040': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)\\\\(ADMIN\\$|C\\$|\\\\\\\\)") AND match(TargetFilename,"(?i)\\.(exe|dll|bat|ps1)$")
| stats count values(TargetFilename) as files by ComputerName, User, _time
| table _time, ComputerName, User, files, count`,
  qradarQuery: `SELECT sourceip, username, destinationip,
  Filename,
  COUNT(*) as tool_transfers
FROM events
WHERE QIDNAME(qid) ILIKE '%File Create%'
  AND (Filename ILIKE '%ADMIN$%' OR Filename ILIKE '%C$%')
  AND (Filename ILIKE '%.exe' OR Filename ILIKE '%.dll' OR Filename ILIKE '%.ps1')
GROUP BY sourceip, username, destinationip, Filename
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0041': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(7z|rar|zip|tar|WinRAR|WinZip)\\.exe$")
  AND match(CommandLine,"(?i)(\\\\Users\\\\|\\\\Documents\\\\|\\\\Desktop\\\\|\\\\Shares\\\\)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as archive_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%7z.exe' OR Filename ILIKE '%rar.exe' OR Filename ILIKE '%zip.exe' OR Filename ILIKE '%WinRAR%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0042': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(keylog|GetAsyncKeyState|SetWindowsHookEx|keyboard.*hook|logkeys)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as keylog_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%keylog%' OR Command ILIKE '%GetAsyncKeyState%' OR Command ILIKE '%SetWindowsHookEx%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0043': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(screenshot|screen.*capture|CopyFromScreen|BitBlt|PrintWindow|snippingtool)")
  OR match(Image,"(?i)(nircmd|screenshot)\\.exe$")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as screenshot_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%screenshot%' OR Command ILIKE '%CopyFromScreen%' OR Command ILIKE '%BitBlt%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0044': {
  splunkQuery: `index=dns sourcetype=dns
| eval query_len=len(query)
| where query_len > 50 OR match(query,"(?i)([a-z0-9]{15,}\\.)") 
| bin _time span=15m
| stats count avg(query_len) as avg_len dc(query) as unique_queries by src_ip, _time
| where count > 100 OR avg_len > 40
| table _time, src_ip, count, avg_len, unique_queries`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as dns_queries,
  COUNT(DISTINCT "DNS Request Domain") as unique_domains
FROM events
WHERE CATEGORYNAME(category) ILIKE '%DNS%'
  AND LENGTH("DNS Request Domain") > 50
GROUP BY sourceip
HAVING COUNT(*) > 100
ORDER BY dns_queries DESC
LAST 4 HOURS`
},

'SR-0045': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where (match(Image,"certutil\\.exe$") AND match(CommandLine,"(?i)(-urlcache|-decode|http)"))
  OR (match(Image,"bitsadmin\\.exe$") AND match(CommandLine,"(?i)(/transfer|/addfile|http)"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as tool_transfer
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ((Filename ILIKE '%certutil%' AND (Command ILIKE '%-urlcache%' OR Command ILIKE '%http%'))
    OR (Filename ILIKE '%bitsadmin%' AND (Command ILIKE '%transfer%' OR Command ILIKE '%http%')))
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0046': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(anydesk|teamviewer|ammyy|logmein|screenconnect|rustdesk|meshagent)\\.exe$")
  AND NOT match(ParentImage,"(?i)(services|explorer)\\.exe$")
| table _time, ComputerName, User, Image, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as rat_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%anydesk%' OR Filename ILIKE '%teamviewer%' OR Filename ILIKE '%screenconnect%'
    OR Filename ILIKE '%rustdesk%' OR Filename ILIKE '%meshagent%')
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0047': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(ssh|plink|putty|chisel|ngrok)\\.exe$")
  AND match(CommandLine,"(?i)(-[LRD]\\s|tunnel|forward|proxy|socks)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as tunnel_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%ssh%' OR Filename ILIKE '%plink%' OR Filename ILIKE '%chisel%' OR Filename ILIKE '%ngrok%')
  AND (Command ILIKE '%-L %' OR Command ILIKE '%-R %' OR Command ILIKE '%tunnel%' OR Command ILIKE '%socks%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0048': {
  splunkQuery: `index=proxy sourcetype=proxy (url="*dropbox.com*" OR url="*drive.google.com*" OR url="*mega.nz*" OR url="*wetransfer.com*" OR url="*sendspace.com*")
| where bytes_out > 10000000
| eval size_mb=round(bytes_out/1024/1024,2)
| stats sum(size_mb) as total_mb count by src_ip, user, dest, _time
| where total_mb > 50
| table _time, user, src_ip, dest, total_mb, count`,
  qradarQuery: `SELECT sourceip, username, url,
  SUM(LONG(bytesout)) as total_bytes,
  COUNT(*) as upload_count
FROM events
WHERE (url ILIKE '%dropbox.com%' OR url ILIKE '%drive.google.com%' OR url ILIKE '%mega.nz%' OR url ILIKE '%wetransfer.com%')
  AND LONG(bytesout) > 10000000
GROUP BY sourceip, username, url
HAVING SUM(LONG(bytesout)) > 50000000
ORDER BY total_bytes DESC
LAST 24 HOURS`
},

'SR-0049': {
  splunkQuery: `index=firewall sourcetype=firewall direction=outbound
| bin _time span=1h
| stats sum(bytes_out) as total_bytes dc(dest_ip) as unique_dests by src_ip, _time
| eval total_gb=round(total_bytes/1073741824,2)
| where total_gb > 0.5
| table _time, src_ip, total_gb, unique_dests`,
  qradarQuery: `SELECT sourceip,
  SUM(LONG(bytesout)) as total_bytes_out,
  COUNT(DISTINCT destinationip) as unique_dests
FROM events
WHERE eventdirection = 'L2R'
GROUP BY sourceip
HAVING SUM(LONG(bytesout)) > 500000000
ORDER BY total_bytes_out DESC
LAST 4 HOURS`
},

'SR-0050': {
  splunkQuery: `index=dns sourcetype=dns query_type=TXT
| eval query_len=len(query)
| where query_len > 50
| bin _time span=15m
| stats count sum(query_len) as total_chars dc(query) as unique_queries by src_ip, query, _time
| where count > 50
| table _time, src_ip, query, count, total_chars, unique_queries`,
  qradarQuery: `SELECT sourceip,
  "DNS Request Domain",
  COUNT(*) as dns_queries,
  SUM(LENGTH("DNS Request Domain")) as total_chars
FROM events
WHERE CATEGORYNAME(category) ILIKE '%DNS%'
  AND (eventname ILIKE '%TXT%' OR LENGTH("DNS Request Domain") > 50)
GROUP BY sourceip, "DNS Request Domain"
HAVING COUNT(*) > 50
ORDER BY dns_queries DESC
LAST 4 HOURS`
},

'SR-0051': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)\\.(encrypted|locked|crypt|enc|ransom|pay2decrypt)$")
| bin _time span=5m
| stats count dc(TargetFilename) as unique_files by ComputerName, User, _time
| where unique_files > 50
| table _time, ComputerName, User, unique_files, count`,
  qradarQuery: `SELECT sourceip, username,
  COUNT(*) as encrypted_files,
  COUNT(DISTINCT Filename) as unique_files
FROM events
WHERE QIDNAME(qid) ILIKE '%File Create%'
  AND (Filename ILIKE '%.encrypted' OR Filename ILIKE '%.locked' OR Filename ILIKE '%.crypt')
GROUP BY sourceip, username
HAVING COUNT(DISTINCT Filename) > 50
ORDER BY encrypted_files DESC
LAST 2 HOURS`
},

'SR-0052': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as recovery_inhibit
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%vssadmin%delete%' OR Command ILIKE '%shadowcopy%delete%'
    OR Command ILIKE '%bcdedit%recoveryenabled%no%' OR Command ILIKE '%wbadmin%delete%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0053': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:System EventCode=7036 OR sourcetype=WinEventLog:Sysmon EventCode=1)
| where (match(ServiceName,"(?i)(MSSQL|Exchange|SQL|IIS|Apache|nginx|veeam)") AND match(Message,"stopped"))
  OR (match(CommandLine,"(?i)(net\\s+stop|sc\\s+stop)") AND match(CommandLine,"(?i)(MSSQL|Exchange|SQL|IIS|veeam)"))
| table _time, ComputerName, User, ServiceName, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Service Name",
  QIDNAME(qid) as event_name,
  COUNT(*) as service_stops
FROM events
WHERE (EventID = 7036 AND eventname ILIKE '%stopped%'
  AND ("Service Name" ILIKE '%SQL%' OR "Service Name" ILIKE '%Exchange%' OR "Service Name" ILIKE '%IIS%'))
  OR (Command ILIKE '%net stop%' AND (Command ILIKE '%SQL%' OR Command ILIKE '%Exchange%'))
GROUP BY sourceip, username, "Service Name", qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0054': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(shutdown\\s+/[rsf]|Restart-Computer|Stop-Computer|init\\s+[06])")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as shutdown_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%shutdown%/s%' OR Command ILIKE '%shutdown%/r%'
    OR Command ILIKE '%Restart-Computer%' OR Command ILIKE '%Stop-Computer%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0055': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(format\\s+[a-z]:|cipher\\s+/w|sdelete|diskpart.*clean|dd\\s+if=/dev/zero)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as wipe_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%format%:' OR Command ILIKE '%cipher%/w%' OR Command ILIKE '%sdelete%'
    OR Command ILIKE '%diskpart%clean%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

// ═══ PART 3: SR-0056 to SR-0070 ═══

'SR-0056': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)mshta\\.exe$")
  AND match(CommandLine,"(?i)(javascript:|vbscript:|http:|https:|about:)")
| table _time, ComputerName, User, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as mshta_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%mshta.exe'
  AND (Command ILIKE '%javascript:%' OR Command ILIKE '%vbscript:%' OR Command ILIKE '%http:%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0057': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)regsvr32\\.exe$")
  AND match(CommandLine,"(?i)(/s|/i:|scrobj|http)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as regsvr32_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%regsvr32.exe'
  AND (Command ILIKE '%/s%' OR Command ILIKE '%/i:%' OR Command ILIKE '%scrobj%' OR Command ILIKE '%http%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0058': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(netsh\\s+advfirewall.*add|netsh\\s+firewall.*add|New-NetFirewallRule)")
  AND match(CommandLine,"(?i)(allow|enable|disable)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as fw_rule_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%netsh%advfirewall%add%' OR Command ILIKE '%New-NetFirewallRule%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0059': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(reg\\s+save.*sam|reg\\s+save.*system|reg\\s+save.*security|secretsdump|pwdump|fgdump)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as sam_access
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%reg save%sam%' OR Command ILIKE '%reg save%system%'
    OR Command ILIKE '%secretsdump%' OR Command ILIKE '%pwdump%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0060': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(Responder|Inveigh|mitm6|NBNSpoof)\\.exe$")
  OR match(CommandLine,"(?i)(Responder\\.py|Inveigh|LLMNR|NBNS|MDNS|poisoning)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as poisoning_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%Responder%' OR Command ILIKE '%Inveigh%'
    OR Command ILIKE '%LLMNR%' OR Command ILIKE '%NBNS%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0061': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(Rubeus.*ptt|kerberos::ptt|kirbi|ccache|klist\\s+purge)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as ptt_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%Rubeus%ptt%' OR Command ILIKE '%kerberos::ptt%'
    OR Command ILIKE '%kirbi%' OR Command ILIKE '%klist%purge%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0062': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(MMC20\\.Application|ShellWindows|ShellBrowserWindow|DCOMExec|dcomexec)")
  OR (match(ParentImage,"(?i)mmc\\.exe$") AND match(Image,"(?i)(cmd|powershell)\\.exe$"))
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as dcom_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%MMC20.Application%' OR Command ILIKE '%ShellWindows%'
    OR Command ILIKE '%DCOMExec%' OR Command ILIKE '%dcomexec%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0063': {
  splunkQuery: `index=proxy sourcetype=proxy ssl=true
| where match(ssl_issuer,"(?i)(Let's Encrypt|self-signed|unknown|localhost)")
  OR ssl_validity_days < 30
| stats count dc(dest) as unique_dests by src_ip, ssl_issuer, ssl_subject, _time
| where count > 10
| table _time, src_ip, ssl_issuer, ssl_subject, unique_dests, count`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as suspicious_tls,
  COUNT(DISTINCT destinationip) as unique_destinations
FROM events
WHERE CATEGORYNAME(category) ILIKE '%SSL%'
  AND (eventname ILIKE '%self-signed%' OR eventname ILIKE '%untrusted%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 10
ORDER BY suspicious_tls DESC
LAST 24 HOURS`
},

'SR-0064': {
  splunkQuery: `index=proxy sourcetype=proxy
| where match(dest,"(?i)(cloudfront\\.net|azureedge\\.net|fastly\\.net|akamai)")
  AND match(url_domain,"(?i)(pastebin|githubusercontent|discord)")
| stats count dc(url_domain) as domains by src_ip, dest, _time
| table _time, src_ip, dest, domains, count`,
  qradarQuery: `SELECT sourceip, destinationip, url,
  COUNT(*) as cdn_c2
FROM events
WHERE (url ILIKE '%cloudfront.net%' OR url ILIKE '%azureedge.net%' OR url ILIKE '%fastly.net%')
GROUP BY sourceip, destinationip, url
HAVING COUNT(*) > 20
ORDER BY cdn_c2 DESC
LAST 24 HOURS`
},

'SR-0065': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(Get-MailboxItem|Search-Mailbox|New-MailboxExportRequest|export-mailbox)")
  OR (match(CommandLine,"(?i)(outlook|msg|eml|pst)") AND match(CommandLine,"(?i)(copy|move|compress|archive)"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as email_collection
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%Search-Mailbox%' OR Command ILIKE '%MailboxExportRequest%'
    OR Command ILIKE '%export-mailbox%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0066': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(robocopy|xcopy|copy)") AND match(CommandLine,"(?i)(\\\\\\\\|\\$)")
  AND match(CommandLine,"(?i)(\\.(docx|xlsx|pdf|pptx|sql|db|csv|key|pem))")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as staging_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%robocopy%' OR Command ILIKE '%xcopy%')
  AND (Command ILIKE '%\\\\%' OR Command ILIKE '%$%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0067': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:System EventCode=7045 OR sourcetype=WinEventLog:Sysmon EventCode=1)
| where match(ServiceName,"(?i)PSEXE") OR match(ImagePath,"(?i)PSEXE")
  OR match(CommandLine,"(?i)(psexec|\\\\\\\\.*\\\\ADMIN\\$)")
| table _time, ComputerName, User, ServiceName, ImagePath, CommandLine`,
  qradarQuery: `SELECT sourceip, username, destinationip,
  QIDNAME(qid) as event_name,
  COUNT(*) as psexec_events
FROM events
WHERE (eventname ILIKE '%PSEXE%' OR Command ILIKE '%psexec%' OR "Service Name" ILIKE '%PSEXE%')
GROUP BY sourceip, username, destinationip, qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0068': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(attrib\\s+\\+h|attrib\\s+\\+s\\s+\\+h|Set-ItemProperty.*Hidden)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as hidden_file_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%attrib%+h%' OR Command ILIKE '%Hidden%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0069': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(findstr.*password|dir.*\\.kdbx|dir.*\\.key|type.*id_rsa|type.*\\.pem|LaZagne|mimikatz|credential)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as cred_discovery
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%findstr%password%' OR Command ILIKE '%.kdbx%' OR Command ILIKE '%id_rsa%'
    OR Command ILIKE '%LaZagne%' OR Command ILIKE '%mimikatz%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0070': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(certutil.*-encode|base64.*encode|ConvertTo-Base64|gzip|compress)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as encoding_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%certutil%-encode%' OR Command ILIKE '%base64%encode%'
    OR Command ILIKE '%ConvertTo-Base64%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

// ═══ PART 4: SR-0071 to SR-0080 ═══

'SR-0071': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=7
| where NOT match(ImageLoaded,"(?i)C:\\\\(Windows|Program Files)")
  AND match(Image,"(?i)(OneDriveUpdater|SearchProtocolHost|colorcpl|msdt|presentationhost)\\.exe$")
| table _time, ComputerName, Image, ImageLoaded, Signed, Signature, Hashes`,
  qradarQuery: `SELECT sourceip, username,
  Filename, "Loaded Module",
  COUNT(*) as sideload_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Image Load%'
  AND (Filename ILIKE '%OneDriveUpdater%' OR Filename ILIKE '%colorcpl%')
  AND "Loaded Module" NOT ILIKE '%Windows\\System32%'
GROUP BY sourceip, username, Filename, "Loaded Module"
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0072': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Security EventCode=4769)
| where match(CommandLine,"(?i)(kerberos::golden|golden_ticket|Rubeus|ticketer\\.py)")
  OR (EventCode=4769 AND NOT [search EventCode=4768 | rename TargetUserName as gt_user | fields gt_user])
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as golden_events
FROM events
WHERE (eventname ILIKE '%kerberos::golden%' OR eventname ILIKE '%golden_ticket%'
  OR eventname ILIKE '%Rubeus%' OR Command ILIKE '%kerberos::golden%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY golden_events DESC
LAST 24 HOURS`
},

'SR-0073': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)schtasks\\.exe$") AND match(CommandLine,"/create")
  AND match(CommandLine,"(?i)(/ru\\s+(SYSTEM|\"NT AUTHORITY\")|\\\\Temp\\\\|powershell|-enc\\s|AppData)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as task_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%schtasks.exe'
  AND Command ILIKE '%/create%'
  AND (Command ILIKE '%SYSTEM%' OR Command ILIKE '%\\Temp\\%' OR Command ILIKE '%powershell%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0074': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(accessTokens\\.json|azureProfile\\.json|TokenCache\\.dat|\\.aws\\\\credentials|Get-AzAccessToken|gcloud.*print-access-token)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as cloud_cred_access
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%accessTokens.json%' OR Command ILIKE '%aws\\credentials%'
    OR Command ILIKE '%Get-AzAccessToken%' OR Command ILIKE '%gcloud%access-token%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0075': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104)
| where match(CommandLine,"(?i)(IEX.*New-Object.*Net\\.WebClient.*DownloadString|Invoke-WebRequest.*\\|.*IEX|iwr.*-uri.*\\|.*iex)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as cradle_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%IEX%DownloadString%' OR Command ILIKE '%Invoke-WebRequest%IEX%'
    OR Command ILIKE '%iwr%-uri%iex%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0076': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval wmi_type=case(EventCode=19,"Filter",EventCode=20,"Consumer",EventCode=21,"Binding")
| stats count values(wmi_type) as components values(Name) as names by ComputerName, User, _time
| table _time, ComputerName, User, components, names, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as wmi_persistence
FROM events
WHERE QIDNAME(qid) ILIKE '%WMI%'
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0077': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(ntdsutil.*ifm|ntdsutil.*create full|vssadmin.*create shadow.*ntds|ntds\\.dit|secretsdump|impacket)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as ntds_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%ntdsutil%ifm%' OR Command ILIKE '%ntds.dit%'
    OR Command ILIKE '%secretsdump%' OR Command ILIKE '%vssadmin%create shadow%ntds%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0078': {
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(svchost|explorer|RuntimeBroker|dllhost)\\.exe$")
  AND match(ParentImage,"(?i)(cmd|powershell|wscript|cscript|mshta)\\.exe$")
  AND NOT match(ParentImage,"(?i)services\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path", Filename,
  COUNT(*) as hollowing_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%svchost.exe' OR Filename ILIKE '%explorer.exe' OR Filename ILIKE '%dllhost.exe')
  AND ("Parent Process Path" ILIKE '%cmd.exe' OR "Parent Process Path" ILIKE '%powershell.exe' OR "Parent Process Path" ILIKE '%wscript.exe')
GROUP BY sourceip, username, "Parent Process Path", Filename
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0079': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Microsoft-Windows-Windows_Defender/Operational EventCode=5007)
| where match(CommandLine,"(?i)(Add-MpPreference|Set-MpPreference).*(ExclusionPath|ExclusionExtension|ExclusionProcess)")
  OR (match(Image,"(?i)reg\\.exe$") AND match(CommandLine,"(?i)Windows Defender\\\\Exclusions"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as defender_exclusion
FROM events
WHERE (Command ILIKE '%Add-MpPreference%Exclusion%' OR Command ILIKE '%Set-MpPreference%Exclusion%'
  OR (Filename ILIKE '%reg.exe' AND Command ILIKE '%Windows Defender\\Exclusions%'))
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
},

'SR-0080': {
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104)
| where match(CommandLine,"(?i)(Get-Clipboard|\\[System\\.Windows\\.Forms\\.Clipboard\\]|GetClipboardData|OpenClipboard)")
  OR match(ScriptBlockText,"(?i)(Get-Clipboard|Clipboard)")
| table _time, ComputerName, User, CommandLine, ScriptBlockText`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as clipboard_events
FROM events
WHERE (Command ILIKE '%Get-Clipboard%' OR Command ILIKE '%Clipboard%GetText%'
  OR Command ILIKE '%GetClipboardData%' OR Command ILIKE '%OpenClipboard%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`
}

};

// ═══ APPLY PATCHES TO SIGMA_RULES ═══
if (typeof SIGMA_RULES !== 'undefined') {
  SIGMA_RULES.forEach(rule => {
    const patch = SIEM_QUERY_PATCH[rule.id];
    if (patch) {
      if (patch.splunkQuery) rule.splunkQuery = patch.splunkQuery;
      if (patch.qradarQuery) rule.qradarQuery = patch.qradarQuery;
    }
  });
  console.log(`[SigmaGuard] Patched ${Object.keys(SIEM_QUERY_PATCH).length} rules with SPL/AQL queries`);
}
