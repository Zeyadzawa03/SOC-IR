// Sigma Rules Database - Part 11: Coverage Expansion — Ransomware, Collection, Cloud, Initial Access
const SIGMA_RULES_PART11 = [
// ═══════════════════════════════════════════════════════════════
// RANSOMWARE
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0196', title: 'Volume Shadow Copy Deletion — Ransomware Pre-Encryption',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2025-01-15', modified: '2025-04-01',
  category: 'ransomware',
  description: 'Detects deletion of Volume Shadow Copies via vssadmin.exe or wmic.exe, a hallmark pre-encryption step performed by nearly all ransomware families to prevent data recovery.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Volume Shadow Copy Deletion — Ransomware Pre-Encryption
id: aa196001-0001-4a00-b000-000000000001
status: stable
description: Detects VSS deletion commonly performed before ransomware encryption
author: SOC Platform
date: 2025/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\\\\vssadmin.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'resize shadowstorage'
    selection_wmic:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains: 'shadowcopy delete'
    selection_ps:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains: 'Win32_ShadowCopy'
    condition: selection_vssadmin or selection_wmic or selection_ps
falsepositives:
    - Legitimate backup software managing shadow copies
level: critical
tags:
    - attack.impact
    - attack.t1490`,
  detectionExplanation: 'Ransomware operators delete Volume Shadow Copies before encryption to prevent victims from restoring files without paying the ransom. This detection monitors for vssadmin, wmic, and PowerShell-based shadow copy deletion, which is one of the highest-confidence ransomware indicators.',
  requiredLogs: ['Sysmon Event ID 1 (Process Creation)', 'Windows Security Event ID 4688'],
  logConfig: 'Enable Sysmon with process creation logging and command line capture.',
  falsePositives: ['Backup software managing VSS storage', 'Disk cleanup scripts run by IT'],
  tuning: 'Allowlist known backup solutions (Veeam, Commvault) by parent process. Alert immediately on any non-allowlisted VSS deletion.',
  commonErrors: ['PowerShell-based deletion not monitored', 'WMI deletion path missed'],
  responseActions: ['IMMEDIATELY isolate the endpoint from the network', 'Capture memory dump before shutdown', 'Check for ransomware note files', 'Identify the ransomware family from IOCs', 'Activate incident response plan for ransomware', 'Assess backup integrity'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Royal Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},
{
  id: 'SR-0197', title: 'Ransomware File Encryption Pattern — Mass File Rename',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2025-01-20', modified: '2025-04-01',
  category: 'ransomware',
  description: 'Detects mass file rename operations with known ransomware extensions (.encrypted, .locked, .crypt, .ransom) indicating active file encryption by ransomware.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Ransomware File Encryption Pattern — Mass File Rename
id: aa196001-0002-4a00-b000-000000000002
status: stable
description: Detects mass file renames with ransomware-associated extensions
author: SOC Platform
date: 2025/01/20
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypt'
            - '.ransom'
            - '.pay2key'
            - '.blackcat'
            - '.lockbit'
            - '.royal'
            - '.hive'
            - '.conti'
    condition: selection
falsepositives:
    - Legitimate encryption software
level: critical
tags:
    - attack.impact
    - attack.t1486`,
  detectionExplanation: 'When ransomware encrypts files, it typically appends distinctive extensions. Monitoring file rename events for known ransomware extensions provides high-confidence detection during active encryption. By the time this triggers, encryption is in progress — immediate response is critical.',
  requiredLogs: ['Sysmon Event ID 11 (File Creation)', 'Sysmon Event ID 2 (File Modification)'],
  logConfig: 'Deploy Sysmon with file event monitoring enabled.',
  falsePositives: ['Legitimate disk encryption tools (VeraCrypt)', 'File extension testing by developers'],
  tuning: 'Set threshold for 10+ file renames with ransomware extensions within 60 seconds to reduce false positives.',
  commonErrors: ['New ransomware families with unknown extensions not covered', 'High volume may overwhelm SIEM'],
  responseActions: ['IMMEDIATELY isolate endpoint — encryption is ACTIVE', 'Kill the encrypting process if identifiable', 'Disconnect network shares to prevent spread', 'Preserve encrypted samples for decryption analysis', 'Check for ransom note and identify ransomware family'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1486/']
},
{
  id: 'SR-0198', title: 'BCDEdit Boot Configuration Tampering',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2025-01-22', modified: '2025-04-01',
  category: 'ransomware',
  description: 'Detects bcdedit.exe used to disable automatic recovery and safe boot options, a technique used by ransomware to prevent system recovery after encryption.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: BCDEdit Boot Configuration Tampering
id: aa196001-0003-4a00-b000-000000000003
status: stable
description: Detects bcdedit used to disable recovery features
author: SOC Platform
date: 2025/01/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled no'
            - 'bootstatuspolicy ignoreallfailures'
            - 'safeboot'
    condition: selection
falsepositives:
    - System administrators configuring boot options
level: critical
tags:
    - attack.impact
    - attack.t1490`,
  detectionExplanation: 'Ransomware uses bcdedit.exe to disable Windows recovery mode and ignore boot failures. This prevents victims from using Safe Mode or Startup Repair to recover from the attack. Combined with VSS deletion, this creates a comprehensive recovery prevention strategy.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security Event ID 4688'],
  logConfig: 'Standard process creation logging with command line auditing.',
  falsePositives: ['IT administrators configuring kiosk or embedded systems', 'Dual-boot configuration changes'],
  tuning: 'Correlate with VSS deletion events for high-confidence ransomware detection. Allowlist known IT management scripts.',
  commonErrors: ['bcdedit run through cmd.exe wrapper not captured', 'Case-sensitive matching missing variations'],
  responseActions: ['Isolate the endpoint immediately', 'Check for concurrent VSS deletion', 'Scan for ransomware payloads', 'Restore boot configuration from known-good backup', 'Activate ransomware IR playbook'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'Royal Ransomware', 'Black Basta'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},
{
  id: 'SR-0199', title: 'Ransomware Note File Creation',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2025-02-01', modified: '2025-04-01',
  category: 'ransomware',
  description: 'Detects creation of known ransomware ransom note filenames across the filesystem, confirming active ransomware compromise.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Ransomware Note File Creation
id: aa196001-0004-4a00-b000-000000000004
status: stable
description: Detects creation of known ransomware ransom note filenames
author: SOC Platform
date: 2025/02/01
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - 'README_TO_RESTORE'
            - 'HOW_TO_DECRYPT'
            - 'DECRYPT_FILES'
            - 'RECOVER_YOUR_FILES'
            - 'ransom_note'
            - 'YOUR_FILES_ARE_ENCRYPTED'
            - 'RESTORE-MY-FILES'
            - '!README!'
    condition: selection
falsepositives:
    - Security researchers testing ransomware samples
level: critical
tags:
    - attack.impact
    - attack.t1486`,
  detectionExplanation: 'Ransomware always drops ransom notes to instruct victims on payment. Monitoring for creation of files with common ransom note naming patterns provides definitive confirmation of a ransomware attack in progress.',
  requiredLogs: ['Sysmon Event ID 11 (File Creation)'],
  logConfig: 'Sysmon with file creation monitoring across all drives.',
  falsePositives: ['Malware analysis sandbox testing', 'Security training simulations'],
  tuning: 'No tuning needed — this is a high-fidelity indicator with near-zero false positive rate.',
  commonErrors: ['File creation events not captured on network shares', 'New ransomware families may use unique note names'],
  responseActions: ['Confirm ransomware family from note content', 'Isolate ALL affected systems', 'Activate enterprise-wide ransomware response', 'Engage legal and executive leadership', 'Contact law enforcement (FBI IC3/CISA)', 'Assess backup availability for recovery'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Royal Ransomware', 'Black Basta'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1486/']
},
{
  id: 'SR-0200', title: 'Windows Backup Catalog Deletion — wbadmin',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2025-02-05', modified: '2025-04-01',
  category: 'ransomware',
  description: 'Detects use of wbadmin.exe to delete the Windows backup catalog or system state backups, preventing recovery from ransomware.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Windows Backup Catalog Deletion — wbadmin
id: aa196001-0005-4a00-b000-000000000005
status: stable
description: Detects wbadmin used to delete backup catalog
author: SOC Platform
date: 2025/02/05
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\wbadmin.exe'
        CommandLine|contains:
            - 'delete catalog'
            - 'delete systemstatebackup'
            - 'delete backup'
    condition: selection
falsepositives:
    - Legitimate backup rotation scripts
level: high
tags:
    - attack.impact
    - attack.t1490`,
  detectionExplanation: 'wbadmin.exe manages Windows Server Backup. Ransomware operators use it to delete backup catalogs to ensure victims cannot restore from local backups. This is typically seen alongside vssadmin and bcdedit tampering.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Process creation logging with command line capture.',
  falsePositives: ['Backup rotation scripts that delete old catalogs', 'Storage migration procedures'],
  tuning: 'Correlate with VSS deletion and bcdedit tampering for maximum confidence.',
  commonErrors: ['wbadmin not monitored on workstations (server-focused)'],
  responseActions: ['Isolate the system', 'Check for concurrent ransomware indicators', 'Verify off-site backup integrity', 'Preserve evidence for forensic analysis'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'Black Basta'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},

// ═══════════════════════════════════════════════════════════════
// COLLECTION (TA0009)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0201', title: 'Automated Data Collection from Local System',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2025-02-10', modified: '2025-04-01',
  category: 'collection',
  description: 'Detects automated collection of sensitive files from common user directories (Documents, Desktop, Downloads) using command-line tools like robocopy, xcopy, or PowerShell.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1005', techniqueName: 'Data from Local System',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Automated Data Collection from Local System
id: aa196001-0006-4a00-b000-000000000006
status: stable
description: Detects bulk file collection from user directories via CLI tools
author: SOC Platform
date: 2025/02/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\\\robocopy.exe'
            - '\\\\xcopy.exe'
            - '\\\\forfiles.exe'
    selection_targets:
        CommandLine|contains:
            - '\\\\Documents\\\\'
            - '\\\\Desktop\\\\'
            - '\\\\Downloads\\\\'
            - '\\\\Contacts\\\\'
    selection_ps:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains:
            - 'Get-ChildItem'
            - 'Copy-Item'
            - 'dir /s'
        CommandLine|contains:
            - '.docx'
            - '.xlsx'
            - '.pdf'
            - '.pst'
    condition: (selection_tools and selection_targets) or selection_ps
falsepositives:
    - IT backup scripts
    - User migration tools
level: high
tags:
    - attack.collection
    - attack.t1005`,
  detectionExplanation: 'Attackers and insiders use CLI tools to systematically collect sensitive documents before exfiltration. This detection monitors for bulk copy operations targeting user profile directories, especially when targeting document types commonly containing sensitive data.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Process creation logging with full command line capture.',
  falsePositives: ['IT-managed backup and migration scripts', 'User-initiated file organization'],
  tuning: 'Allowlist known backup tools by hash. Focus on non-admin users performing bulk collection.',
  commonErrors: ['PowerShell copy operations using aliases not captured', 'UNC path collection missed'],
  responseActions: ['Investigate the user account and recent activity', 'Check for staging directories', 'Look for subsequent exfiltration activity', 'Interview the user if insider threat suspected'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1005/']
},
{
  id: 'SR-0202', title: 'Email Mailbox Collection — PST Export',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2025-02-12', modified: '2025-04-01',
  category: 'collection',
  description: 'Detects export of Outlook mailbox data to PST files or access to existing PST files, commonly used by attackers to collect email data for exfiltration.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1114.001', techniqueName: 'Local Email Collection',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Email Mailbox Collection — PST Export
id: aa196001-0007-4a00-b000-000000000007
status: stable
description: Detects PST file export or access for email collection
author: SOC Platform
date: 2025/02/12
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains:
            - 'New-MailboxExportRequest'
            - 'Export-Mailbox'
            - '.pst'
    selection_copy:
        Image|endswith:
            - '\\\\robocopy.exe'
            - '\\\\xcopy.exe'
            - '\\\\copy.exe'
        CommandLine|contains: '.pst'
    condition: selection_ps or selection_copy
falsepositives:
    - Authorized email archival
    - Legal hold collection
level: high
tags:
    - attack.collection
    - attack.t1114.001`,
  detectionExplanation: 'Email contains highly sensitive organizational data. Attackers export mailboxes to PST files for offline browsing and exfiltration. This detection monitors for PST-related PowerShell cmdlets and file copy operations.',
  requiredLogs: ['Sysmon Event ID 1', 'Exchange Admin Audit Logs'],
  logConfig: 'Enable Exchange admin audit logging. Deploy Sysmon on mail servers.',
  falsePositives: ['Legal eDiscovery processes', 'Authorized email migration', 'User-initiated mailbox backup'],
  tuning: 'Correlate with authorized export requests via ticketing system. Alert on export by non-Exchange admin accounts.',
  commonErrors: ['Exchange Online PowerShell exports not monitored on-premises', 'PST auto-archival generating noise'],
  responseActions: ['Verify export authorization against change management', 'Check destination of PST files', 'Review Exchange admin audit logs', 'Suspend account if unauthorized'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'APT29'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1114/001/']
},
{
  id: 'SR-0203', title: 'Network Share Enumeration and Data Staging',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2025-02-15', modified: '2025-04-01',
  category: 'collection',
  description: 'Detects enumeration of network shares followed by staging of collected data, indicating preparation for exfiltration of shared network drive content.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1039', techniqueName: 'Data from Network Shared Drive',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Network Share Enumeration and Data Staging
id: aa196001-0008-4a00-b000-000000000008
status: stable
description: Detects network share browsing and bulk data staging
author: SOC Platform
date: 2025/02/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_enum:
        Image|endswith: '\\\\net.exe'
        CommandLine|contains:
            - 'view'
            - 'share'
            - 'use'
    selection_bulk_copy:
        Image|endswith:
            - '\\\\robocopy.exe'
            - '\\\\xcopy.exe'
        CommandLine|contains: '\\\\\\\\'
    condition: selection_enum or selection_bulk_copy
falsepositives:
    - Network administrators auditing shares
    - Automated backup scripts
level: medium
tags:
    - attack.collection
    - attack.t1039`,
  detectionExplanation: 'Before exfiltration, attackers enumerate available network shares and copy large volumes of data to staging directories. This detection monitors for share enumeration commands and bulk copy operations targeting UNC paths.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security Event ID 5140'],
  logConfig: 'Enable object access auditing for network shares. Deploy Sysmon.',
  falsePositives: ['IT staff performing share audits', 'Scheduled backup operations', 'File server migrations'],
  tuning: 'Focus on non-admin users accessing multiple shares in rapid succession. Correlate with archiving activity.',
  commonErrors: ['Net.exe vs net1.exe aliasing not captured', 'Mapped drive access not logged as UNC'],
  responseActions: ['Review the user account and access patterns', 'Check what data was accessed from shares', 'Look for subsequent archiving or exfiltration', 'Verify authorization for share access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1039/']
},

// ═══════════════════════════════════════════════════════════════
// CLOUD THREATS
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0204', title: 'AWS IAM Access Key Created for Persistence',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2025-02-20', modified: '2025-04-01',
  category: 'cloud-threats',
  description: 'Detects creation of new IAM access keys in AWS, which can be used by attackers to maintain persistent access to cloud resources after initial compromise.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1098.001', techniqueName: 'Additional Cloud Credentials',
  logsource: { product: 'aws', service: 'cloudtrail' },
  sigmaYaml: `title: AWS IAM Access Key Created for Persistence
id: aa196001-0009-4a00-b000-000000000009
status: stable
description: Detects IAM access key creation in AWS CloudTrail
author: SOC Platform
date: 2025/02/20
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'CreateAccessKey'
    filter_service:
        userIdentity.type: 'AssumedRole'
        userIdentity.sessionContext.sessionIssuer.userName|startswith: 'AWSServiceRole'
    condition: selection and not filter_service
falsepositives:
    - Authorized key rotation
    - CI/CD pipeline key management
level: high
tags:
    - attack.persistence
    - attack.t1098.001`,
  detectionExplanation: 'IAM access keys provide programmatic access to AWS. Attackers create new keys for persistence — even if the original compromise vector is remediated, the new keys remain valid. This detection monitors CloudTrail for CreateAccessKey events outside of normal service role operations.',
  requiredLogs: ['AWS CloudTrail logs', 'AWS IAM audit events'],
  logConfig: 'Enable CloudTrail logging with management events. Forward to SIEM.',
  falsePositives: ['Scheduled key rotation processes', 'DevOps teams creating pipeline credentials', 'New employee onboarding'],
  tuning: 'Baseline normal key creation patterns. Alert on key creation for accounts that already have active keys or during off-hours.',
  commonErrors: ['CloudTrail not forwarded to SIEM', 'Assumed role events not properly parsed'],
  responseActions: ['Verify key creation was authorized', 'Check if the creating user is compromised', 'Disable the new access key if unauthorized', 'Review CloudTrail for other suspicious API calls by the same user', 'Rotate credentials for affected account'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1098/001/']
},
{
  id: 'SR-0205', title: 'Azure AD Conditional Access Policy Modification',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2025-02-22', modified: '2025-04-01',
  category: 'cloud-threats',
  description: 'Detects modification or deletion of Azure AD Conditional Access policies, which could indicate an attacker weakening security controls after gaining admin access.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'azure', service: 'auditlogs' },
  sigmaYaml: `title: Azure AD Conditional Access Policy Modification
id: aa196001-0010-4a00-b000-000000000010
status: stable
description: Detects changes to Azure AD Conditional Access policies
author: SOC Platform
date: 2025/02/22
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName|contains:
            - 'Update conditional access policy'
            - 'Delete conditional access policy'
    condition: selection
falsepositives:
    - Authorized policy changes by security team
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  detectionExplanation: 'Conditional Access policies enforce MFA, device compliance, and location-based restrictions. Modifying or disabling these policies is a critical defense evasion technique that allows attackers to bypass security controls for compromised accounts.',
  requiredLogs: ['Azure AD Audit Logs', 'Azure Sentinel/Microsoft 365 logs'],
  logConfig: 'Enable Azure AD audit logging. Forward to SIEM via Azure Event Hub or diagnostic settings.',
  falsePositives: ['Security team updating CA policies during change windows', 'Policy testing in development tenants'],
  tuning: 'Correlate with change management tickets. Alert on policy deletion or disabling outside of approved windows.',
  commonErrors: ['Azure AD logs not ingested into on-premises SIEM', 'Policy changes via Graph API not monitored'],
  responseActions: ['Verify the change was authorized via change management', 'Check the admin account for compromise', 'Restore the original CA policy immediately if unauthorized', 'Review Azure AD sign-in logs for suspicious auth patterns', 'Enable MFA on all admin accounts'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
}
];

// Register Part 11
if (typeof SIGMA_RULES !== 'undefined') {
  SIGMA_RULES.push(...SIGMA_RULES_PART11);
  console.log('[SigmaGuard] Loaded Part 11:', SIGMA_RULES_PART11.length, 'rules (SR-0196 to SR-0205)');
}
