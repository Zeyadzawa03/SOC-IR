// ═══════════════════════════════════════════════════════════════════════
// Incident Response (IR) Engine — Embedded IR Playbooks per Detection
// Integrates directly into each Sigma rule / detection page
// ═══════════════════════════════════════════════════════════════════════

const IR_PLAYBOOKS = {
  // ── Category-Based IR Playbooks ──
  'brute-force': {
    name: 'Brute Force / Credential Stuffing Response',
    severity: 'high',
    investigationSteps: [
      'Identify the source IP(s) generating failed authentication attempts',
      'Determine which accounts were targeted (single account vs. password spraying)',
      'Check if any successful login followed the brute force pattern',
      'Review proxy/VPN logs to confirm external vs internal origin',
      'Query SIEM for same source IP across all authentication systems',
      'Check if source IP appears in threat intelligence feeds',
      'Determine if MFA was triggered and whether it was bypassed',
      'Review historical authentication patterns for targeted accounts'
    ],
    requiredLogs: [
      'Windows Security Event Log (4624, 4625, 4648, 4776)',
      'VPN/Remote Access authentication logs',
      'Azure AD / Entra ID Sign-in logs',
      'Web application authentication logs',
      'Firewall connection logs (source IP tracking)',
      'Email gateway logs (credential phishing check)'
    ],
    indicatorsToCheck: [
      'Multiple failed logins from same source IP (>10 in 5 minutes)',
      'Failed logins targeting multiple accounts from single IP (password spray)',
      'Geographic anomaly — login from unusual country/region',
      'Time anomaly — authentication attempts during off-hours',
      'User agent string anomalies (automated tools vs. browsers)',
      'Successful login following series of failures (compromise indicator)',
      'Account lockout events correlating with failed login surge',
      'MFA challenge failures or bypass attempts'
    ],
    containmentActions: [
      'Block attacking IP(s) at perimeter firewall immediately',
      'Lock targeted accounts if compromise is suspected',
      'Force password reset for any account with successful login post-brute-force',
      'Enable or enforce MFA on all targeted accounts',
      'Add source IP(s) to block lists across all authentication endpoints',
      'Isolate any endpoint where successful login occurred',
      'Disable VPN access for compromised accounts'
    ],
    escalationSteps: [
      'Escalate to SOC Lead if successful authentication detected post-brute-force',
      'Engage Identity team for mass account lockout/reset if spray attack confirmed',
      'Notify CISO if privileged accounts were targeted',
      'Open incident ticket — priority based on account compromise status',
      'Engage threat intelligence team to attribute source IP',
      'If credential compromise confirmed → escalate to full IR'
    ],
    evidenceCollection: [
      'Export authentication logs for full attack window (+/- 24 hours)',
      'Capture firewall logs showing source IP connections',
      'Screenshot SIEM dashboard showing attack pattern',
      'Export account lockout events',
      'Collect VPN concentrator logs',
      'Preserve MFA audit logs'
    ]
  },

  'ransomware': {
    name: 'Ransomware Incident Response',
    severity: 'critical',
    investigationSteps: [
      'IMMEDIATELY isolate affected systems from network (do NOT power off)',
      'Identify the ransomware variant from ransom note / encrypted file extensions',
      'Determine initial access vector (phishing, exploit, RDP, etc.)',
      'Map the blast radius — identify all encrypted/affected systems',
      'Check for data exfiltration indicators (double extortion)',
      'Identify the threat actor group if possible',
      'Determine the encryption timeline — when did encryption start',
      'Check backup integrity — are backups intact and accessible',
      'Review Shadow Copy / VSS status on affected systems',
      'Assess Active Directory compromise status'
    ],
    requiredLogs: [
      'Sysmon Process Creation (Event ID 1) — encryption process',
      'File Creation/Modification logs (Sysmon Event ID 11)',
      'Windows Security Log — account activity',
      'Network connection logs — C2 communication',
      'DNS logs — domain resolution patterns',
      'Email gateway logs — initial phishing vector',
      'Backup system logs — backup deletion attempts',
      'VSS/Shadow Copy deletion events (vssadmin)'
    ],
    indicatorsToCheck: [
      'Mass file extension changes (.encrypted, .locked, .crypt)',
      'Ransom note files dropped in multiple directories',
      'VSS/Shadow Copy deletion commands (vssadmin delete shadows)',
      'BCDEdit boot configuration changes',
      'Suspicious PowerShell/CMD execution chains',
      'Network scanning from compromised hosts',
      'Large outbound data transfers (double extortion)',
      'Lateral movement indicators (PsExec, WMI, RDP)',
      'Group Policy Object (GPO) abuse for mass deployment',
      'Anti-virus/EDR tampering or disabling'
    ],
    containmentActions: [
      'ISOLATE all affected systems immediately — pull network cable/disable WiFi',
      'Isolate entire network segment if spread is rapid',
      'Disable compromised accounts in Active Directory',
      'Block known C2 domains/IPs at DNS and firewall',
      'Disconnect backup systems from network to prevent encryption',
      'Disable Remote Desktop Protocol (RDP) enterprise-wide if used as vector',
      'Take domain controllers offline if AD compromise suspected',
      'Implement emergency firewall rules to segment network',
      'Preserve at least one encrypted system for forensic analysis'
    ],
    escalationSteps: [
      'Immediately notify CISO and executive leadership',
      'Engage external incident response firm (retainer)',
      'Contact legal counsel — assess notification requirements',
      'Notify cyber insurance provider',
      'Consider law enforcement notification (FBI IC3, CISA)',
      'DO NOT communicate with threat actor without legal guidance',
      'Activate Business Continuity Plan',
      'Prepare internal and external communications',
      'Assess regulatory notification requirements (GDPR, HIPAA, etc.)'
    ],
    evidenceCollection: [
      'Create forensic images of affected systems (before remediation)',
      'Capture memory dumps of running ransomware processes',
      'Collect ransom note samples from multiple systems',
      'Export all SIEM logs for the incident timeline',
      'Preserve network packet captures if available',
      'Screenshot encrypted file listings with timestamps',
      'Collect process execution trees from EDR',
      'Preserve email with initial phishing lure'
    ]
  },

  'web-attacks': {
    name: 'Web Application Attack Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the exploited vulnerability (CVE, OWASP category)',
      'Review web server access logs for exploit payload patterns',
      'Determine if webshell was deployed post-exploitation',
      'Check for unauthorized file creation in web root directories',
      'Review web application firewall (WAF) logs for blocked/allowed attacks',
      'Analyze the attacker\'s full request chain (recon → exploit → post-exploit)',
      'Check for database compromise (SQL injection: exported data, new accounts)',
      'Determine if the attacker pivoted from web server to internal network'
    ],
    requiredLogs: [
      'Web server access logs (IIS/Apache/Nginx)',
      'Web application firewall (WAF) logs',
      'Sysmon Process Creation on web servers',
      'Database audit logs',
      'Network connection logs from web server',
      'File integrity monitoring (FIM) alerts',
      'Application-level error logs',
      'Reverse proxy logs'
    ],
    indicatorsToCheck: [
      'Unusual POST requests with encoded/obfuscated payloads',
      'Web server process spawning command shells (cmd.exe, bash)',
      'New files created in web root directories (webshells)',
      'Database queries with UNION, SELECT, or xp_cmdshell',
      'Outbound connections from web server to unusual destinations',
      'HTTP response size anomalies (data exfiltration)',
      'Directory traversal patterns (../../../)',
      'Encoded payloads in URL parameters or POST body'
    ],
    containmentActions: [
      'Implement WAF rule to block exploit pattern',
      'Isolate the web server if compromise confirmed',
      'Remove webshell files and restore clean versions',
      'Patch the vulnerable application/component',
      'Reset database credentials if SQL injection confirmed',
      'Review and revoke any created admin accounts',
      'Block attacker IP ranges at WAF/firewall',
      'Rotate API keys and secrets accessible from web server'
    ],
    escalationSteps: [
      'Notify application development team for emergency patching',
      'Engage web application security team for code review',
      'Escalate to SOC Lead if data exfiltration detected',
      'Notify compliance team if customer data exposed',
      'If database compromise → full data breach response',
      'Engage third-party penetration testing for verification'
    ],
    evidenceCollection: [
      'Export full web server access logs for attack period',
      'Capture webshell files with metadata preserved',
      'Collect modified/created files in web directories',
      'Export WAF event logs',
      'Database query logs showing malicious commands',
      'Network captures of exploit traffic',
      'Process execution history from web server'
    ]
  },

  'reconnaissance': {
    name: 'Reconnaissance / Discovery Activity Response',
    severity: 'medium',
    investigationSteps: [
      'Identify the scanning source (internal vs external)',
      'Determine scan type (port scan, vulnerability scan, directory enumeration)',
      'Check if scanning precedes any exploitation attempts',
      'Review firewall logs for systematic connection attempts',
      'Correlate with any recent threat intelligence advisories',
      'Check if the source IP belongs to a known scanning service',
      'Assess whether internal scanning is authorized (pen test, vulnerability assessment)'
    ],
    requiredLogs: [
      'Firewall connection logs',
      'IDS/IPS alerts',
      'Network flow data (NetFlow/sFlow)',
      'DNS query logs',
      'Web server access logs',
      'Proxy logs'
    ],
    indicatorsToCheck: [
      'Rapid sequential port connections from single source',
      'HTTP requests to non-existent pages (directory brute-force)',
      'DNS queries for internal hostnames from external source',
      'SNMP, LDAP, or SMB enumeration from unexpected sources',
      'Version-specific HTTP requests (banner grabbing)',
      'Systematic scanning patterns across IP ranges'
    ],
    containmentActions: [
      'Block scanning IP at perimeter firewall',
      'Add source to threat intelligence watchlist',
      'Enable rate limiting for the source IP',
      'Review and harden exposed services',
      'Verify no exploitation followed reconnaissance'
    ],
    escalationSteps: [
      'Escalate if scanning targets critical infrastructure',
      'Notify threat intelligence team for attribution',
      'If internal source — verify authorization or investigate compromise',
      'Log incident for trend analysis'
    ],
    evidenceCollection: [
      'Firewall logs showing scan patterns',
      'IDS/IPS alert exports',
      'Network flow data for scanning period',
      'DNS query logs from scanning source'
    ]
  },

  'insider-threat': {
    name: 'Insider Threat Investigation Response',
    severity: 'high',
    investigationSteps: [
      'Identify the user account and their role/access level',
      'Review data access patterns — unusual file access or downloads',
      'Check for bulk data collection or staging activities',
      'Review email logs for external data transmission',
      'Check USB device connection history',
      'Review cloud storage sync/upload activity',
      'Analyze print logs for sensitive document printing',
      'Review VPN/remote access patterns — off-hours activity',
      'Check HR records — recent termination notice, performance issues',
      'Review DLP (Data Loss Prevention) alerts'
    ],
    requiredLogs: [
      'Windows Security Event Log (File access auditing)',
      'DLP system alerts and logs',
      'Email gateway logs (attachments, external recipients)',
      'Cloud storage audit logs (OneDrive, SharePoint, Box)',
      'USB device connection events',
      'Proxy/web filter logs',
      'Print server logs',
      'VPN authentication and session logs',
      'Badge access / physical security logs'
    ],
    indicatorsToCheck: [
      'Abnormally large file downloads or data staging',
      'Access to files outside normal job function',
      'Email to personal accounts with attachments',
      'USB mass storage device connections on restricted systems',
      'Cloud sync to unauthorized services',
      'Off-hours access to sensitive repositories',
      'Bulk printing of sensitive documents',
      'Account activity after resignation/termination notice'
    ],
    containmentActions: [
      'Do NOT alert the user initially (coordinate with HR/Legal first)',
      'Enable enhanced monitoring on the user\'s accounts',
      'Apply DLP policies to prevent further data exfiltration',
      'Restrict USB access on user\'s endpoints',
      'Block personal cloud storage access for the user',
      'Coordinate with HR and Legal before any confrontation',
      'Preserve all evidence before account changes'
    ],
    escalationSteps: [
      'Immediately involve HR and Legal departments',
      'Notify CISO for risk assessment',
      'Engage digital forensics if evidence collection needed',
      'If theft of trade secrets suspected — consider law enforcement',
      'Document chain of custody for all evidence',
      'Prepare for potential litigation hold'
    ],
    evidenceCollection: [
      'Full forensic image of user\'s workstation',
      'Email archive export for investigation period',
      'DLP alert history and data flow logs',
      'Cloud storage audit trail',
      'USB device connection history',
      'Badge access / physical entry logs',
      'Network traffic analysis for data staging'
    ]
  },

  'cloud-threats': {
    name: 'Cloud Security Incident Response',
    severity: 'high',
    investigationSteps: [
      'Identify compromised cloud account(s) and access scope',
      'Review cloud audit trail (AWS CloudTrail, Azure Activity Log, GCP Audit)',
      'Check for unauthorized resource creation (VMs, storage, accounts)',
      'Identify API keys or tokens that may have been exposed',
      'Review IAM policy changes and role modifications',
      'Check for data access to sensitive storage (S3, Blob, GCS)',
      'Verify MFA status on compromised accounts',
      'Check for cryptocurrency mining resource creation'
    ],
    requiredLogs: [
      'Cloud provider audit logs (CloudTrail, Azure Monitor, GCP Audit)',
      'IAM change logs',
      'Storage access logs',
      'Network flow logs (VPC Flow Logs)',
      'SSO/Identity Provider logs',
      'Cloud WAF/Shield logs'
    ],
    indicatorsToCheck: [
      'API calls from unusual geographic locations',
      'New IAM users or roles with admin privileges',
      'Storage bucket policy changes (public access)',
      'Large data downloads from storage services',
      'Unusual compute instance creation (crypto mining)',
      'Security group/firewall rule modifications',
      'Programmatic access without MFA',
      'Root/owner account usage'
    ],
    containmentActions: [
      'Rotate all credentials for compromised accounts',
      'Revoke active sessions and API tokens',
      'Disable unauthorized IAM users/roles',
      'Restore modified security groups/policies',
      'Delete unauthorized compute resources',
      'Enable MFA on all accounts',
      'Apply SCPs/policies to restrict unauthorized actions',
      'Block malicious IP addresses at cloud firewall'
    ],
    escalationSteps: [
      'Notify cloud security team immediately',
      'Contact cloud provider security (AWS Shield, Azure Security)',
      'Engage incident response if data breach suspected',
      'Assess financial impact of unauthorized resource usage',
      'Review compliance implications'
    ],
    evidenceCollection: [
      'Export cloud audit logs for investigation period',
      'Capture IAM policy snapshots (before/after)',
      'Export storage access logs',
      'Document unauthorized resources with timestamps',
      'Capture network flow logs'
    ]
  },

  'active-directory': {
    name: 'Active Directory Compromise Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the compromised account(s) and privilege level',
      'Check for Kerberoasting activity (SPN queries, ticket requests)',
      'Review DCSync or DCShadow indicators',
      'Check for Golden/Silver Ticket usage',
      'Review Group Policy Object modifications',
      'Check for new admin accounts or group membership changes',
      'Review trust relationship changes',
      'Analyze KRBTGT account status',
      'Check for NTDS.dit extraction attempts',
      'Review replication topology changes'
    ],
    requiredLogs: [
      'Windows Security Event Log (4768, 4769, 4770, 4771, 4672)',
      'Domain Controller event logs',
      'Sysmon on Domain Controllers',
      'LDAP query logs',
      'Group Policy change events',
      'Replication event logs',
      'PowerShell Script Block Logging on DCs',
      'DNS Server logs on DCs'
    ],
    indicatorsToCheck: [
      'Kerberos TGS requests for service accounts (Kerberoasting)',
      'DC replication from non-DC source (DCSync)',
      'KRBTGT password changes (Golden Ticket remediation)',
      'AdminSDHolder permission modifications',
      'Suspicious LDAP queries (BloodHound collection)',
      'PowerShell AD module usage from non-admin workstations',
      'DRS replication requests from unknown sources',
      'Certificate template modifications (AD CS abuse)',
      'Group nesting changes for privileged groups'
    ],
    containmentActions: [
      'Reset compromised account passwords immediately',
      'Reset KRBTGT password TWICE (with replication between resets)',
      'Disable compromised accounts',
      'Remove unauthorized group memberships',
      'Revert GPO changes to known-good state',
      'Block lateral movement ports (445, 135, 5985)',
      'Isolate compromised domain controllers',
      'Enable enhanced DC monitoring'
    ],
    escalationSteps: [
      'CRITICAL — Engage IR team immediately for any DC compromise',
      'Notify CISO — AD compromise affects entire environment',
      'Consider full AD recovery if KRBTGT compromised',
      'Engage Microsoft DART or equivalent AD recovery specialist',
      'Prepare for potential full forest recovery',
      'Assess impact on all domain-joined systems',
      'Evaluate trust relationships with other domains'
    ],
    evidenceCollection: [
      'Export all DC security event logs',
      'Capture AD database snapshots',
      'Export Group Policy status',
      'Document group membership changes',
      'Preserve replication metadata',
      'Capture LDAP query logs',
      'Export Certificate Services audit logs'
    ]
  },

  'email-threats': {
    name: 'Email Threat / Phishing Response',
    severity: 'high',
    investigationSteps: [
      'Obtain the original email with full headers',
      'Analyze sender domain, SPF/DKIM/DMARC results',
      'Extract and analyze URLs (use sandbox, avoid clicking)',
      'Extract and analyze attachments (submit to sandbox)',
      'Determine how many recipients received the email',
      'Identify which users clicked links or opened attachments',
      'Check if any users submitted credentials to phishing page',
      'Review email gateway logs for similar messages'
    ],
    requiredLogs: [
      'Email gateway logs (message tracking)',
      'Mail flow / transport rules logs',
      'URL click tracking (if available)',
      'Endpoint process creation logs (attachment execution)',
      'Proxy logs (URL access after click)',
      'Authentication logs (credential compromise check)',
      'Sandbox analysis results'
    ],
    indicatorsToCheck: [
      'Sender domain age (newly registered = suspicious)',
      'SPF/DKIM/DMARC failures',
      'URL redirects to credential harvesting pages',
      'Attachment with macros, scripts, or double extensions',
      'Urgency language in email body',
      'Impersonation of internal executives or vendors',
      'Reply-to address different from sender',
      'Similar emails sent to multiple recipients'
    ],
    containmentActions: [
      'Remove/quarantine the phishing email from all mailboxes',
      'Block sender domain at email gateway',
      'Block phishing URLs at proxy/DNS',
      'Reset passwords for users who submitted credentials',
      'Revoke active sessions for compromised accounts',
      'Enable MFA for affected users',
      'Block attachment hashes at email gateway',
      'Send user awareness notification'
    ],
    escalationSteps: [
      'Escalate if executive impersonation detected (BEC)',
      'Notify all affected users immediately',
      'If credentials compromised → check for data access',
      'If malware delivered → escalate to malware response playbook',
      'Report phishing infrastructure for takedown',
      'Update email security rules organization-wide'
    ],
    evidenceCollection: [
      'Save original email (.eml) with full headers',
      'Screenshot of phishing page',
      'Sandbox analysis report for attachments',
      'URL analysis report',
      'Email gateway logs showing delivery details',
      'List of all recipients and click status'
    ]
  },

  'network-anomalies': {
    name: 'Network Anomaly Investigation Response',
    severity: 'medium',
    investigationSteps: [
      'Identify the anomalous traffic pattern (C2, tunneling, beaconing)',
      'Analyze source/destination IPs and ports',
      'Check DNS query patterns for DGA or tunneling',
      'Review network flow data for data exfiltration indicators',
      'Correlate with endpoint telemetry on source hostname',
      'Check if destination IPs appear in threat intelligence feeds',
      'Analyze protocol anomalies (DNS over HTTPS, ICMP tunneling)',
      'Review SSL/TLS certificate details of destination'
    ],
    requiredLogs: [
      'Firewall/NGFW connection logs',
      'DNS query logs',
      'Proxy/web filter logs',
      'Network flow data (NetFlow/sFlow)',
      'IDS/IPS alerts',
      'SSL/TLS inspection logs',
      'Packet capture (if available)'
    ],
    indicatorsToCheck: [
      'Regular beaconing intervals (C2 communication)',
      'Long DNS TXT queries (DNS tunneling)',
      'HTTPS connections to IP addresses (no domain)',
      'Unusual port usage for standard protocols',
      'High-entropy domain names (DGA)',
      'Large outbound data transfers during off-hours',
      'Connections to known bad IP/domain indicators',
      'Protocol mismatches (HTTP over non-standard ports)'
    ],
    containmentActions: [
      'Block suspicious destination IPs/domains at firewall',
      'Isolate the source endpoint for investigation',
      'Implement DNS sinkholing for suspicious domains',
      'Block the malicious communication protocol/port',
      'Enable enhanced monitoring on affected network segment'
    ],
    escalationSteps: [
      'Escalate if C2 communication confirmed',
      'Engage network security team for deep packet inspection',
      'If data exfiltration detected → notify data protection team',
      'Update threat intelligence with new IOCs'
    ],
    evidenceCollection: [
      'Export network flow data for suspicious connections',
      'Capture DNS query logs',
      'Packet captures of anomalous traffic',
      'IDS/IPS alert details',
      'Firewall logs for source endpoint'
    ]
  },

  'endpoint-anomalies': {
    name: 'Endpoint Anomaly Response',
    severity: 'high',
    investigationSteps: [
      'Identify the anomalous process or behavior',
      'Review process execution tree (parent → child chain)',
      'Check for process injection indicators',
      'Review memory usage anomalies',
      'Analyze loaded DLLs for suspicious modules',
      'Check file system changes by the suspicious process',
      'Review network connections established by the process',
      'Verify process signature and legitimacy'
    ],
    requiredLogs: [
      'Sysmon Process Creation (Event ID 1)',
      'Sysmon Process Access (Event ID 10)',
      'Sysmon Image Load (Event ID 7)',
      'EDR telemetry',
      'Windows Security Process events',
      'Memory analysis tools output'
    ],
    indicatorsToCheck: [
      'Process injection (CreateRemoteThread, APC injection)',
      'Unsigned processes in system directories',
      'Process hollowing indicators',
      'Suspicious DLL side-loading',
      'Living-off-the-land binary (LOLBin) abuse',
      'Memory-only payloads (fileless malware)',
      'Process masquerading (svchost from wrong path)',
      'API hooking or ETW patching'
    ],
    containmentActions: [
      'Isolate the endpoint from network',
      'Kill the suspicious process and prevent restart',
      'Collect memory dump before termination',
      'Block the process hash across all endpoints',
      'Check for persistence mechanisms',
      'Run full EDR scan on the endpoint'
    ],
    escalationSteps: [
      'Escalate if process injection or fileless malware confirmed',
      'Engage malware analysis team for sample review',
      'If lateral movement detected → escalate to network-wide hunt',
      'Notify SOC Lead for enterprise-wide IOC sweep'
    ],
    evidenceCollection: [
      'Process memory dump',
      'Process execution tree with full command lines',
      'Loaded module/DLL list',
      'Network connections from the process',
      'File system changes timeline',
      'EDR detection details'
    ]
  },

  'linux-threats': {
    name: 'Linux Threat Response',
    severity: 'high',
    investigationSteps: [
      'Identify the compromised Linux system and its function',
      'Check for unauthorized cron jobs or systemd services',
      'Review SSH authorized_keys for unauthorized entries',
      'Check /tmp, /dev/shm for suspicious files',
      'Review bash_history for all users',
      'Check for rootkit indicators (hidden processes, modules)',
      'Review iptables/nftables modifications',
      'Check for unauthorized SUID/SGID binaries'
    ],
    requiredLogs: [
      'syslog / journalctl',
      'auth.log / secure',
      'audit.log (auditd)',
      'wtmp / btmp (login records)',
      'cron logs',
      'Apache/Nginx access logs (if web server)',
      'Package manager logs (apt/yum history)'
    ],
    indicatorsToCheck: [
      'New cron jobs executing scripts from /tmp',
      'SSH keys added to authorized_keys',
      'Reverse shell connections (nc, bash -i, python)',
      'Kernel module loading (insmod, modprobe)',
      'File modifications in /etc (passwd, shadow, sudoers)',
      'SUID binary creation or modification',
      'Process running from /tmp or /dev/shm',
      'Network listeners on unusual ports'
    ],
    containmentActions: [
      'Disable network access (iptables DROP all)',
      'Kill suspicious processes',
      'Remove unauthorized SSH keys',
      'Remove malicious cron jobs',
      'Block connecting IPs at firewall',
      'Change all passwords on the system',
      'Remove unauthorized SUID binaries'
    ],
    escalationSteps: [
      'Escalate if rootkit detected — system is unreliable',
      'If production server — coordinate with operations team',
      'If web server compromised — activate web attack playbook',
      'Consider rebuilding system from known-good image'
    ],
    evidenceCollection: [
      'Copy of auth.log, syslog, audit.log',
      'Full filesystem timeline (find with timestamps)',
      'Process listing (ps auxwww)',
      'Network connections (netstat -tulpn)',
      'Cron job listings for all users',
      'SSH authorized_keys from all users',
      'Bash history files'
    ]
  },

  'windows-specific': {
    name: 'Windows-Specific Threat Response',
    severity: 'high',
    investigationSteps: [
      'Identify the LOLBin or Windows utility being abused',
      'Review the full command line and parameters',
      'Check the parent process legitimacy',
      'Analyze if AMSI bypass was attempted',
      'Check for AppLocker/WDAC bypass indicators',
      'Review Windows Defender exclusions for suspicious paths',
      'Check for COM object hijacking',
      'Review WMI repository for persistence'
    ],
    requiredLogs: [
      'Sysmon (all events)',
      'Windows Security Log',
      'PowerShell Script Block Logging',
      'Windows Defender operational log',
      'AMSI logging',
      'AppLocker logs'
    ],
    indicatorsToCheck: [
      'LOLBin abuse (certutil, mshta, regsvr32, rundll32)',
      'AMSI bypass patterns in PowerShell',
      'DLL search order hijacking',
      'COM object hijacking (registry modifications)',
      'Alternate Data Streams (ADS) usage',
      'Windows Defender exclusion modifications',
      'Reflective DLL injection',
      'Direct syscall usage (EDR bypass)'
    ],
    containmentActions: [
      'Block the specific LOLBin abuse pattern',
      'Apply AppLocker/WDAC policies',
      'Remove malicious registry entries',
      'Restore Windows Defender configuration',
      'Block the attack hash enterprise-wide',
      'Isolate endpoint for forensic analysis'
    ],
    escalationSteps: [
      'Escalate if EDR bypass confirmed',
      'Notify security engineering to update detection rules',
      'If AMSI bypass → update PowerShell constraints',
      'Share IOCs with threat intelligence team'
    ],
    evidenceCollection: [
      'Full Sysmon event export',
      'PowerShell transcript logs',
      'Registry snapshots',
      'Windows Defender event logs',
      'Process memory dumps',
      'ETW trace data'
    ]
  },

  'data-exfiltration': {
    name: 'Data Exfiltration Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the data being exfiltrated (type, classification, volume)',
      'Determine the exfiltration method (email, cloud, DNS, HTTP)',
      'Identify the user/process responsible',
      'Quantify the data loss (number of records, file size)',
      'Determine if data was encrypted before exfiltration',
      'Check if staging activity preceded exfiltration',
      'Identify the destination (personal account, C2 server, competitor)',
      'Determine the timeline of data collection and transfer'
    ],
    requiredLogs: [
      'DLP alerts and event logs',
      'Proxy/web filter logs',
      'Email gateway logs (attachment tracking)',
      'Cloud storage audit logs',
      'USB device connection events',
      'Network flow data (volume analysis)',
      'DNS query logs (DNS tunneling check)',
      'File access audit logs'
    ],
    indicatorsToCheck: [
      'Large outbound data transfers (unusual volume)',
      'Data uploads to personal cloud storage',
      'Emails with large attachments to external addresses',
      'Archive files (zip, rar, 7z) created before transfer',
      'DNS tunneling (long TXT queries, high query volume)',
      'USB device connections and file copies',
      'Print jobs for sensitive documents',
      'Screen capture or clipboard data exfiltration'
    ],
    containmentActions: [
      'Block the exfiltration channel immediately',
      'Disable the responsible user account (if insider)',
      'Kill the exfiltration process (if automated)',
      'Apply DLP block policies',
      'Disconnect the endpoint from network',
      'Revoke access to sensitive data repositories',
      'Block the destination IP/domain at firewall'
    ],
    escalationSteps: [
      'CRITICAL — Notify CISO and Legal immediately',
      'Engage data privacy/compliance team',
      'Assess regulatory notification requirements',
      'If intentional insider threat → coordinate with HR/Legal',
      'If external attacker → escalate to full IR',
      'Initiate breach notification process if required',
      'Preserve chain of custody for legal proceedings'
    ],
    evidenceCollection: [
      'DLP event logs and policy match details',
      'Network traffic captures showing exfiltration',
      'Email logs with attachment details',
      'File access audit trail',
      'User activity timeline',
      'Copy of exfiltrated data (for impact assessment)',
      'Cloud storage activity logs'
    ]
  },

  'lateral-movement': {
    name: 'Lateral Movement Response',
    severity: 'high',
    investigationSteps: [
      'Identify the source and destination of lateral movement',
      'Determine the method used (RDP, WMI, PsExec, SSH)',
      'Check the credentials/account used for movement',
      'Map all systems accessed from the initial compromise',
      'Review authentication logs across all targets',
      'Check for Pass-the-Hash or Pass-the-Ticket indicators',
      'Determine if admin tools were deployed on targets'
    ],
    requiredLogs: [
      'Windows Security Event Log (4624 Type 3/10, 4648)',
      'Sysmon Network Connection (Event ID 3)',
      'SMB file share access logs',
      'RDP connection logs',
      'WMI event logs',
      'SSH auth logs (Linux targets)',
      'Service installation events (7045)'
    ],
    indicatorsToCheck: [
      'Type 3 logons from workstation to workstation',
      'PsExec service installation (PSEXESVC)',
      'WMI remote process creation',
      'RDP connections between servers/workstations',
      'Pass-the-Hash (NTLM Type 3 without preceding Type 10)',
      'Overpass-the-Hash / Pass-the-Ticket indicators',
      'Remote service creation',
      'Admin share access (C$, ADMIN$)'
    ],
    containmentActions: [
      'Disable the compromised account(s)',
      'Block lateral movement ports between endpoints (445, 3389, 5985)',
      'Isolate all confirmed compromised systems',
      'Reset passwords for accounts used in lateral movement',
      'Implement network segmentation emergency rules',
      'Disable remote services on non-server endpoints'
    ],
    escalationSteps: [
      'Escalate if domain admin credentials used',
      'Map full scope before containment to avoid alerting attacker',
      'If multiple systems compromised → activate major incident process',
      'Engage network team for emergency segmentation',
      'Coordinate containment timing across all compromised systems'
    ],
    evidenceCollection: [
      'Authentication logs from all involved systems',
      'Service installation events',
      'Network connection logs between systems',
      'Process creation logs on destination systems',
      'RDP session recordings if available',
      'File access logs on destination systems'
    ]
  },

  'privilege-escalation': {
    name: 'Privilege Escalation Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the exploit or technique used for escalation',
      'Determine the original (pre-escalation) privilege level',
      'Check what actions were performed with elevated privileges',
      'Review for kernel exploits, UAC bypass, or token manipulation',
      'Check for unquoted service path exploitation',
      'Review DLL hijacking indicators',
      'Check for Group Policy abuse'
    ],
    requiredLogs: [
      'Sysmon Process Creation with integrity level',
      'Windows Security Event Log (4672 — Special Privileges)',
      'UAC elevation events',
      'Service installation events',
      'Token manipulation events',
      'Kernel driver load events (Sysmon Event ID 6)'
    ],
    indicatorsToCheck: [
      'Process running as SYSTEM from user context',
      'UAC bypass techniques (fodhelper, eventvwr)',
      'Token impersonation (Potato exploits)',
      'Named pipe impersonation',
      'Unquoted service path exploitation',
      'DLL side-loading in privileged processes',
      'Kernel driver installation for escalation',
      'Scheduled task running as SYSTEM'
    ],
    containmentActions: [
      'Terminate the escalated process',
      'Patch the escalation vulnerability',
      'Remove the escalation mechanism (malicious service, DLL)',
      'Restrict the original compromised account',
      'Apply least-privilege principle improvements',
      'Block the exploit technique at EDR level'
    ],
    escalationSteps: [
      'Escalate if SYSTEM/root access obtained',
      'If domain admin achieved → activate AD compromise playbook',
      'Notify vulnerability management for patching priority',
      'If kernel exploit used → consider system reinstallation'
    ],
    evidenceCollection: [
      'Process execution tree with integrity levels',
      'Exploit artifacts (dropped files, modified services)',
      'Token and privilege assignment events',
      'UAC elevation event logs',
      'Kernel driver load events',
      'Service configuration changes'
    ]
  },

  'credential-access': {
    name: 'Credential Access / Theft Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the credential theft technique (dumping, keylogging, phishing)',
      'Determine which credentials were compromised',
      'Check for LSASS process access (Mimikatz indicator)',
      'Review SAM database access attempts',
      'Check for NTDS.dit extraction (domain credential theft)',
      'Review brute force or password spraying indicators',
      'Check for credential exposure in logs or scripts'
    ],
    requiredLogs: [
      'Sysmon Process Access (Event ID 10 — LSASS access)',
      'Windows Security Event Log (credential events)',
      'PowerShell Script Block Logging',
      'Sysmon File Creation (credential dump files)',
      'Registry access events (SAM, SECURITY hives)',
      'EDR credential theft alerts'
    ],
    indicatorsToCheck: [
      'LSASS process access from non-system processes',
      'Mimikatz command patterns (sekurlsa, kerberos)',
      'SAM/SECURITY/SYSTEM registry hive access',
      'NTDS.dit file access or Volume Shadow Copy creation',
      'Credential files (.kirbi, .ccache, procdump output)',
      'Browser credential store access',
      'Keylogger process indicators',
      'LaZagne or similar credential harvesting tools'
    ],
    containmentActions: [
      'Reset ALL credentials that may have been exposed',
      'Reset KRBTGT password if domain credentials stolen',
      'Force password change for all affected users',
      'Enable MFA on all compromised accounts',
      'Block the credential theft tool/hash enterprise-wide',
      'Apply LSA protection (RunAsPPL, Credential Guard)',
      'Rotate service account passwords'
    ],
    escalationSteps: [
      'CRITICAL — Any domain credential theft requires immediate escalation',
      'If LSASS dumped on DC → assume full domain compromise',
      'Notify identity team for mass password reset',
      'Engage AD security specialist',
      'If service account credentials stolen → assess blast radius'
    ],
    evidenceCollection: [
      'LSASS access event logs',
      'Process execution details for credential tools',
      'Registry access audit logs',
      'File creation events for dump files',
      'Authentication logs post-compromise',
      'EDR detection artifacts'
    ]
  },

  'defense-evasion': {
    name: 'Defense Evasion Response',
    severity: 'high',
    investigationSteps: [
      'Identify the evasion technique (log clearing, AV disable, timestomping)',
      'Determine what was being hidden by the evasion technique',
      'Check for security tool tampering (AV, EDR, firewall)',
      'Review audit log integrity (cleared, disabled)',
      'Check for process masquerading or naming tricks',
      'Look for timestomping on suspicious files',
      'Check for indicator removal (log deletion, artifact cleanup)'
    ],
    requiredLogs: [
      'Windows Security Event Log (1102 — Log Cleared)',
      'Sysmon Process Tampering events',
      'Windows Defender event log',
      'EDR tamper protection events',
      'File system MAC timestamps',
      'Audit policy change events (4719)'
    ],
    indicatorsToCheck: [
      'Security event log cleared (Event ID 1102)',
      'Audit policy disabled or modified',
      'Windows Defender disabled or excluded paths added',
      'EDR agent stopped or uninstalled',
      'Firewall rules disabled',
      'File timestamp manipulation',
      'Process name mimicking system processes',
      'Sysmon configuration tampering'
    ],
    containmentActions: [
      'Restore security tool configurations',
      'Re-enable audit logging',
      'Reinstall/repair tampered security agents',
      'Restore firewall rules to baseline',
      'Block the evasion tool/technique',
      'Apply tamper protection policies'
    ],
    escalationSteps: [
      'Any EDR/AV tampering indicates sophisticated actor',
      'If audit logs cleared → assume evidence destruction',
      'Engage forensics team for timeline reconstruction',
      'Notify security engineering to harden defenses',
      'Consider deploying additional monitoring'
    ],
    evidenceCollection: [
      'Whatever logs survived the evasion attempt',
      'Security tool event logs',
      'File system timeline analysis',
      'Registry changes related to security tools',
      'EDR tamper protection events',
      'Network-based detection data (as backup)'
    ]
  },

  'persistence': {
    name: 'Persistence Mechanism Response',
    severity: 'high',
    investigationSteps: [
      'Identify the persistence mechanism (registry, service, task, WMI)',
      'Determine when the persistence was established',
      'Analyze the payload that persistence triggers',
      'Check for multiple persistence mechanisms (redundancy)',
      'Review the initial compromise that led to persistence',
      'Check if persistence survives reboot and user logon',
      'Verify if persistence has been active (executed post-reboot)'
    ],
    requiredLogs: [
      'Registry modification events (Sysmon 13)',
      'Service installation events (System 7045)',
      'Scheduled task creation events (Security 4698)',
      'WMI subscription events (Sysmon 19/20/21)',
      'Startup folder file creation (Sysmon 11)',
      'Boot configuration changes'
    ],
    indicatorsToCheck: [
      'Registry Run/RunOnce key modifications',
      'New Windows services pointing to suspicious paths',
      'Scheduled tasks with suspicious commands',
      'WMI event subscriptions',
      'Startup folder file additions',
      'DLL search order hijacking',
      'COM object hijacking',
      'Boot/logon autostart execution'
    ],
    containmentActions: [
      'Remove all identified persistence mechanisms',
      'Kill the persisted payload process',
      'Remove associated malicious files',
      'Verify removal survives reboot',
      'Check for backup persistence mechanisms',
      'Apply preventive controls (GPO, EDR rules)'
    ],
    escalationSteps: [
      'If multiple persistence mechanisms → indicates sophisticated actor',
      'If WMI or COM-based → engage advanced threat team',
      'If domain-level persistence (GPO) → escalate to AD team',
      'Document all persistence for threat intelligence'
    ],
    evidenceCollection: [
      'Registry export of modified keys',
      'Service configuration details',
      'Scheduled task XML configurations',
      'WMI subscription details',
      'Associated malicious files',
      'Timeline of persistence establishment'
    ]
  },

  'execution': {
    name: 'Malicious Execution Response',
    severity: 'high',
    investigationSteps: [
      'Identify the executed payload and execution method',
      'Trace the full execution chain from initial trigger',
      'Determine if execution was user-initiated or automated',
      'Analyze the payload behavior (network, file, registry activity)',
      'Check for follow-up actions (persistence, lateral movement)',
      'Submit payload hash to threat intelligence platforms',
      'Determine if execution was successful or blocked'
    ],
    requiredLogs: [
      'Sysmon Process Creation (Event ID 1)',
      'PowerShell Script Block Logging (4104)',
      'Windows Security Process Creation (4688)',
      'Application Execution logs',
      'EDR detection events'
    ],
    indicatorsToCheck: [
      'Encoded PowerShell commands',
      'Script interpreter spawning child processes',
      'DLL execution via rundll32/regsvr32',
      'MSBuild/InstallUtil abuse (.NET compilation)',
      'Macro execution from Office applications',
      'Exploitation of application vulnerabilities',
      'Binary execution from temp/staging directories'
    ],
    containmentActions: [
      'Kill the malicious process',
      'Block the payload hash enterprise-wide',
      'Remove the malicious file',
      'Check for persistence established by the payload',
      'Reset credentials if credential access detected',
      'Isolate endpoint if post-exploitation activity seen'
    ],
    escalationSteps: [
      'If exploitation of 0-day → notify threat intelligence',
      'If payload contains C2 → activate network analysis',
      'If ransomware payload → activate ransomware playbook',
      'Share IOCs with security operations team'
    ],
    evidenceCollection: [
      'Malicious payload file (preserved safely)',
      'Full process execution tree',
      'PowerShell transcription logs',
      'Network connections from payload',
      'File system changes by payload',
      'Memory dump of payload process'
    ]
  },

  'initial-access': {
    name: 'Initial Access Response',
    severity: 'high',
    investigationSteps: [
      'Determine the initial access vector (phishing, exploit, valid creds)',
      'Identify the timeline of initial compromise',
      'Check what happened immediately after initial access',
      'Review authentication log for the entry point',
      'Determine if the vector is still open for re-entry',
      'Check for similar access across other systems/users'
    ],
    requiredLogs: [
      'Email gateway logs',
      'VPN/remote access logs',
      'Web server access logs',
      'Authentication event logs',
      'proxy logs',
      'Firewall connection logs'
    ],
    indicatorsToCheck: [
      'Phishing email with malicious attachment/link',
      'Exploitation of public-facing application',
      'Compromised valid credentials',
      'Supply chain compromise indicators',
      'Drive-by download indicators',
      'USB/removable media insertion events'
    ],
    containmentActions: [
      'Close the initial access vector immediately',
      'Patch exploited vulnerabilities',
      'Block attacking infrastructure',
      'Reset compromised credentials',
      'Remove phishing emails from all mailboxes',
      'Update security controls to prevent re-entry'
    ],
    escalationSteps: [
      'Determine full scope of compromise from initial access',
      'Engage appropriate response playbook based on impact',
      'Notify security architecture for defense improvements',
      'Update threat intelligence with new initial access indicators'
    ],
    evidenceCollection: [
      'Initial access artifact (email, exploit payload)',
      'Authentication logs from entry point',
      'Network logs showing initial connection',
      'Timeline of post-access activity'
    ]
  },

  'command-control': {
    name: 'Command & Control (C2) Response',
    severity: 'critical',
    investigationSteps: [
      'Identify the C2 protocol and communication channel',
      'Determine the C2 server infrastructure (domains, IPs)',
      'Analyze beaconing patterns (interval, jitter)',
      'Check for data exfiltration over C2 channel',
      'Identify all endpoints communicating with C2',
      'Determine the C2 framework being used (Cobalt Strike, Sliver, etc.)',
      'Check for fallback C2 channels'
    ],
    requiredLogs: [
      'Proxy/web filter logs',
      'DNS query logs',
      'Firewall connection logs',
      'SSL/TLS inspection logs',
      'Network flow data',
      'Endpoint network connection logs'
    ],
    indicatorsToCheck: [
      'Regular interval connections (beaconing)',
      'HTTPS to newly registered domains',
      'DNS tunneling (long queries, TXT records)',
      'Connections to IP addresses without domains',
      'Malleable C2 profile indicators',
      'Named pipe-based C2 (SMB)',
      'HTTP(S) with custom user agents',
      'Cloud service abuse for C2 (Teams, OneDrive, S3)'
    ],
    containmentActions: [
      'Block C2 domains/IPs at DNS and firewall',
      'Sinkhole C2 domains',
      'Isolate all endpoints with C2 communication',
      'Kill C2 beacon processes on endpoints',
      'Block the C2 protocol at proxy',
      'Check for fallback C2 and block those too'
    ],
    escalationSteps: [
      'C2 detection indicates active compromise — CRITICAL',
      'Map all compromised endpoints before mass containment',
      'Coordinate containment timing to prevent attacker adaptation',
      'Engage threat intelligence for C2 framework attribution',
      'Notify executive leadership of active breach',
      'Consider engaging law enforcement for infrastructure takedown'
    ],
    evidenceCollection: [
      'C2 traffic captures (PCAP)',
      'DNS query logs for C2 domains',
      'Endpoint processes running C2 beacons',
      'C2 beacon configuration extraction',
      'Timeline of C2 establishment',
      'Network flow data showing C2 patterns'
    ]
  },

  'collection': {
    name: 'Data Collection Activity Response',
    severity: 'medium',
    investigationSteps: [
      'Identify what data is being collected and by whom',
      'Determine if collection is automated or manual',
      'Check for data staging in temporary directories',
      'Review file access patterns for sensitive data stores',
      'Check for archive creation (zip, rar) for data staging',
      'Determine if collection precedes exfiltration'
    ],
    requiredLogs: [
      'File access audit logs',
      'Sysmon File Creation events',
      'process creation logs (archiving tools)',
      'Email access logs',
      'SharePoint/file share access logs',
      'clipboard access events'
    ],
    indicatorsToCheck: [
      'Bulk file access to sensitive directories',
      'Archive file creation in staging directories',
      'Email collection (PST export, inbox rules)',
      'Screen capture tools execution',
      'Credential database access',
      'Cloud storage bulk downloads'
    ],
    containmentActions: [
      'Restrict access to targeted data stores',
      'Delete staged data archives',
      'Disable the collecting account',
      'Enable DLP monitoring on sensitive data',
      'Block archiving tools if unauthorized'
    ],
    escalationSteps: [
      'If sensitive data collected → notify data protection team',
      'If followed by exfiltration attempt → activate data breach response',
      'Document scope of data accessed for impact assessment'
    ],
    evidenceCollection: [
      'File access audit trail',
      'Staged archive files',
      'Process execution logs for collection tools',
      'Timeline of data access patterns'
    ]
  },

  'threat-hunting': {
    name: 'Proactive Threat Hunt Response',
    severity: 'medium',
    investigationSteps: [
      'Document the hunting hypothesis and methodology',
      'Record all queries and data sources used',
      'Classify findings (confirmed threat, suspicious, benign)',
      'For confirmed threats — transition to IR playbook',
      'For suspicious activity — document and monitor',
      'Update detection rules based on hunt findings'
    ],
    requiredLogs: [
      'All available security telemetry',
      'Endpoint detection data',
      'Network monitoring data',
      'Authentication logs',
      'Application logs'
    ],
    indicatorsToCheck: [
      'Based on current hunting hypothesis',
      'Known IOCs from threat intelligence',
      'Behavioral anomalies identified during hunt',
      'TTP patterns matching known threat actors'
    ],
    containmentActions: [
      'If threat found — escalate to appropriate IR playbook',
      'If potential threat — implement enhanced monitoring',
      'Create new detection rules based on findings',
      'Document and share hunt results'
    ],
    escalationSteps: [
      'Transition to IR if confirmed threat found',
      'Brief SOC leadership on hunt findings',
      'Update threat intelligence with new indicators',
      'Request additional resources if scope increases'
    ],
    evidenceCollection: [
      'Hunt queries and methodology documentation',
      'Screenshots of findings',
      'Log exports supporting findings',
      'Timeline of discovered activity'
    ]
  }
};

// ── Get IR playbook for a specific rule or category ──
function getIRPlaybook(categoryOrRuleId) {
  // Direct category match
  if (IR_PLAYBOOKS[categoryOrRuleId]) {
    return IR_PLAYBOOKS[categoryOrRuleId];
  }

  // Try to find by rule ID
  if (typeof SIGMA_RULES !== 'undefined') {
    const rule = SIGMA_RULES.find(r => r.id === categoryOrRuleId);
    if (rule && rule.category && IR_PLAYBOOKS[rule.category]) {
      return IR_PLAYBOOKS[rule.category];
    }
  }

  // Fallback — generic playbook
  return IR_PLAYBOOKS['endpoint-anomalies'];
}

// ── Get all IR playbooks ──
function getAllIRPlaybooks() {
  return Object.entries(IR_PLAYBOOKS).map(([catId, playbook]) => ({
    categoryId: catId,
    ...playbook
  }));
}

// Make globally accessible
window.IR_PLAYBOOKS = IR_PLAYBOOKS;
window.getIRPlaybook = getIRPlaybook;
window.getAllIRPlaybooks = getAllIRPlaybooks;
