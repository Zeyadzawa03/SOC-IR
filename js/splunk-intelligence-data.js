// ============================================
// SIGMA DETECTION PLATFORM - Splunk Intelligence
// Curated Splunk SPL queries mapped to MITRE ATT&CK and Category workflows
// ============================================

const SPLUNK_INTELLIGENCE_DATA = {
  fundamentals: [
    {
      title: "Basic Search Structure",
      description: "A solid Splunk query always starts with an index, sourcetype, and timeframe.",
      query: "index=windows sourcetype=WinEventLog:Security EventCode=4624",
      useCase: "Find successful logins in Windows security events."
    },
    {
      title: "Filtering & Wildcards",
      description: "Use wildcards (*) and field combinations to filter the noise.",
      query: "index=* sourcetype=suricata src_ip=\"192.168.1.*\" dest_port IN (80, 443, 8080)",
      useCase: "Search network traffic from a specific subnet to common web ports."
    },
    {
      title: "Stats and Aggregation",
      description: "aggregate data to find anomalies or summarize activity.",
      query: "index=windows EventCode=4625 | stats count by TargetUserName, ip_address | where count > 10",
      useCase: "Identify potential brute force attempts by counting failed logins per user and IP."
    },
    {
      title: "Time-based Analytics",
      description: "Use timechart to visualize trends over time.",
      query: "index=firewall action=blocked | timechart count by dest_ip span=1h",
      useCase: "View blocked connection spikes per destination IP over hourly intervals."
    }
  ],
  categories: {
    // 1. Initial Access
    "initial-access": {
      name: "Initial Access",
      tips: [
        "Monitor external-facing application logs (web servers, VPNs) for unusual authentication or exploitation patterns.",
        "Look for initial payloads delivered via email gateways (e.g., unusual attachments, links)."
      ],
      queries: [
        {
          name: "VPN Login from Unexpected Geo",
          query: "index=vpn action=success | iplocation src_ip | search Country!=\"United States\"",
          type: "Hunting"
        },
        {
          name: "Suspicious Office Document Execution",
          query: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1 (Image=\"*\\\\winword.exe\" OR Image=\"*\\\\excel.exe\") (CommandLine=\"*cmd.exe*\" OR CommandLine=\"*powershell.exe*\")",
          type: "Detection"
        }
      ]
    },
    // 2. Execution
    "execution": {
      name: "Execution",
      tips: [
        "Focus on process creation events (Sysmon Event ID 1 or Security Event ID 4688) with command-line auditing enabled.",
        "Track parent-child process anomalies, like Office apps spawning command shells."
      ],
      queries: [
        {
          name: "PowerShell Encoded Command",
          query: "index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine=\"*powershell*\" CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\"",
          type: "Detection"
        },
        {
          name: "Suspicious Parent-Child Process",
          query: "index=windows EventCode=4688 ParentProcessName IN (\"winword.exe\",\"excel.exe\",\"acrobat.exe\") ProcessName IN (\"cmd.exe\",\"powershell.exe\",\"wscript.exe\")",
          type: "Hunting"
        }
      ]
    },
    // 3. Persistence
    "persistence": {
      name: "Persistence",
      tips: [
        "Monitor registry run keys, scheduled tasks, and service creation/modification.",
        "Look for unusual drivers or WMI event subscriptions."
      ],
      queries: [
        {
          name: "Scheduled Task Creation",
          query: "index=windows sourcetype=WinEventLog:Security EventCode=4698 | table _time, host, SubjectUserName, TaskName",
          type: "Detection"
        },
        {
          name: "Registry Run Key Modification",
          query: "index=windows sourcetype=WinEventLog:Sysmon EventCode=13 OR EventCode=14 TargetObject=\"*\\\\CurrentVersion\\\\Run*\"",
          type: "Detection"
        }
      ]
    },
    // 4. Privilege Escalation
    "privilege-escalation": {
      name: "Privilege Escalation",
      tips: [
        "Watch for processes running as SYSTEM that were spawned by user-level processes.",
        "Monitor for abuse of setuid/setgid in Linux or token manipulation in Windows."
      ],
      queries: [
        {
          name: "Process Spawning as SYSTEM",
          query: "index=windows EventCode=4688 TargetLogonId=\"0x3e7\" ParentProcessName!=\"services.exe\" ParentProcessName!=\"smss.exe\"",
          type: "Hunting"
        },
        {
          name: "Named Pipe Impersonation",
          query: "index=windows sourcetype=WinEventLog:Sysmon EventCode=6 OR EventCode=17 OR EventCode=18 | search \"PipeName\"=\"*\\\\lsass\"",
          type: "Detection"
        }
      ]
    },
    // 5. Defense Evasion
    "defense-evasion": {
      name: "Defense Evasion",
      tips: [
        "Audit logs for event log clearing (Event ID 1102, 104) and antivirus tampering.",
        "Look for renamed standard executables or file obfuscation."
      ],
      queries: [
        {
          name: "Event Log Cleared",
          query: "index=windows sourcetype=WinEventLog:Security (EventCode=1102 OR EventCode=104) | table _time, host, SubjectUserName",
          type: "Detection"
        },
        {
          name: "Execution from Suspicious Directory",
          query: "index=windows EventCode=4688 Image IN (\"*\\\\Temp\\\\*\", \"*\\\\AppData\\\\Local\\\\Temp\\\\*\", \"*\\\\ProgramData\\\\*\")",
          type: "Hunting"
        }
      ]
    },
    // 6. Credential Access
    "credential-access": {
      name: "Credential Access",
      tips: [
        "Monitor memory access to lsass.exe (Sysmon Event ID 10) for credential dumping.",
        "Hunt for unusual access to the SAM hive or NTDS.dit."
      ],
      queries: [
        {
          name: "LSASS Memory Access (Mimikatz)",
          query: "index=windows sourcetype=WinEventLog:Sysmon EventCode=10 TargetImage=\"*\\\\lsass.exe\" GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x143a\"",
          type: "Detection"
        },
        {
          name: "Access to NTDS.dit",
          query: "index=windows EventCode=4656 ObjectName=\"*\\\\ntds.dit\"",
          type: "Detection"
        }
      ]
    },
    // 7. Discovery
    "reconnaissance": {
      name: "Discovery / Reconnaissance",
      tips: [
        "Look for rapid execution of enumeration commands (whoami, net user, ipconfig) within a short timeframe.",
        "Monitor for bloodhound/sharphound execution footprints in Windows."
      ],
      queries: [
        {
          name: "Rapid Enumeration Commands",
          query: "index=windows EventCode=4688 ProcessName IN (\"whoami.exe\",\"net.exe\",\"ipconfig.exe\",\"systeminfo.exe\",\"nltest.exe\") | stats count values(ProcessName) as commands by host, SubjectUserName | where count > 3",
          type: "Hunting"
        },
        {
          name: "Suspicious Net User Execution",
          query: "index=windows EventCode=4688 CommandLine=\"*net* user* /domain*\"",
          type: "Detection"
        }
      ]
    },
    // 8. Lateral Movement
    "lateral-movement": {
      name: "Lateral Movement",
      tips: [
        "Analyze authentication logs for Type 3 (Network) logons combined with administrative share access (C$, ADMIN$).",
        "Monitor SMB/RPC traffic and unusual Pass-the-Hash indicators (Event ID 4624 Logon Type 9)."
      ],
      queries: [
        {
          name: "Pass the Hash Indicator",
          query: "index=windows EventCode=4624 LogonType=9 AuthenticationPackage=\"Negotiate\" LogonProcessName=\"seclogo\"",
          type: "Detection"
        },
        {
          name: "Admin Share Access (PSExec)",
          query: "index=windows EventCode=5140 ShareName=\"*\\\\ADMIN$\" OR ShareName=\"*\\\\C$\"",
          type: "Hunting"
        }
      ]
    },
    // 9. Collection
    "collection": {
      name: "Collection",
      tips: [
        "Look for the staging of files in central directories (e.g., Temp, Public) using archiving tools (Rar, 7z, tar).",
        "Monitor for unusual email forwarding rules or mailbox access."
      ],
      queries: [
        {
          name: "Data Staging with Archiving Tool",
          query: "index=windows EventCode=4688 ProcessName IN (\"7z.exe\",\"rar.exe\",\"zip.exe\",\"tar.exe\") CommandLine=\"*-p*\" OR CommandLine=\"*-a*\"",
          type: "Hunting"
        },
        {
          name: "O365 Mailbox Permission Changes",
          query: "index=o365 Workload=Exchange Operation=\"Add-MailboxPermission\" OR Operation=\"Add-MailboxFolderPermission\"",
          type: "Detection"
        }
      ]
    },
    // 10. Command and Control
    "command-control": {
      name: "Command & Control",
      tips: [
        "Analyze firewall and proxy logs for beacons: consistent periodic connections to the same IP/domain.",
        "Look for unusual DNS queries, DGA domains, or long/encoded TXT records indicating DNS tunneling."
      ],
      queries: [
        {
          name: "Potential Beaconing Activity",
          query: "index=firewall | streamstats time_window=10m count as conn_count by src_ip, dest_ip, dest_port | where conn_count > 50",
          type: "Hunting"
        },
        {
          name: "Suspicious DNS TXT Queries",
          query: "index=dns record_type=\"TXT\" | eval len=len(query) | where len > 100",
          type: "Detection"
        }
      ]
    },
    // 11. Data Exfiltration
    "data-exfiltration": {
      name: "Data Exfiltration",
      tips: [
        "Monitor for huge volume of outbound data transfer over a short period to external destinations.",
        "Look for data transfers over unusual ports, or access to known cloud file-sharing services (MEGA, Dropbox) originating from servers."
      ],
      queries: [
        {
          name: "Large Outbound Data Transfer",
          query: "index=firewall action=allowed direction=outbound | stats sum(bytes_out) as total_bytes by src_ip, dest_ip | where total_bytes > 500000000",
          type: "Detection"
        },
        {
          name: "Unexpected Cloud Storage Access",
          query: "index=proxy (url=\"*mega.nz*\" OR url=\"*dropbox.com*\" OR url=\"*drive.google.com*\") | stats count by src_ip, url",
          type: "Hunting"
        }
      ]
    },
    // 12. Brute Force
    "brute-force": {
      name: "Brute Force",
      tips: [
        "Group authentication failures (Event ID 4625) by username and source IP.",
        "Identify 'password spraying' where one IP tries many different usernames."
      ],
      queries: [
        {
          name: "Standard Brute Force",
          query: "index=windows EventCode=4625 | stats count by TargetUserName, IpAddress | where count > 10",
          type: "Detection"
        },
        {
          name: "Password Spraying Attack",
          query: "index=windows EventCode=4625 | stats dc(TargetUserName) as unique_users by IpAddress | where unique_users > 5",
          type: "Detection"
        }
      ]
    },
    // 13. Ransomware
    "ransomware": {
      name: "Ransomware",
      tips: [
        "Look for deletion of Volume Shadow Copies (vssadmin delete shadows).",
        "Monitor for massive file modification/entension changes across file shares."
      ],
      queries: [
        {
          name: "Shadow Copy Deletion",
          query: "index=windows EventCode=4688 CommandLine=\"*vssadmin* delete shadows*\" OR CommandLine=\"*wmic* shadowcopy delete*\"",
          type: "Detection"
        },
        {
          name: "Mass File Renaming (File Share)",
          query: "index=windows EventCode=5145 AccessMask=\"0x120089\" | bucket _time span=1m | stats count by src_ip | where count > 100",
          type: "Hunting"
        }
      ]
    },
    // 14. Web Attacks
    "web-attacks": {
      name: "Web Attacks",
      tips: [
        "Analyze web server access logs or WAF logs for SQLi, XSS, or Directory Traversal payloads in URLs/User-Agents.",
        "Identify spikes in 404s and 403s from a single IP indicating web directory fuzzing."
      ],
      queries: [
        {
          name: "SQL Injection Payload in URL",
          query: "index=web | search url=\"*UNION*SELECT*\" OR url=\"*%27*\" OR url=\"*1=1*\"",
          type: "Detection"
        },
        {
          name: "Web Directory Fuzzing",
          query: "index=web status IN (404, 403) | stats count by src_ip | where count > 100",
          type: "Hunting"
        }
      ]
    },
    // 15. Insider Threat
    "insider-threat": {
      name: "Insider Threat",
      tips: [
        "Monitor off-hours access or massive file downloads by authorized users.",
        "Track USB insertions combined with confidential file access."
      ],
      queries: [
        {
          name: "Off-hours Active Directory Access",
          query: "index=windows EventCode=4624 | eval hour=date_hour | where hour < 6 OR hour > 20 | stats count by TargetUserName",
          type: "Hunting"
        },
        {
          name: "USB Device Connected",
          query: "index=windows EventCode=6416 OR EventCode=2003 | search \"USB\\\\VID*\"",
          type: "Detection"
        }
      ]
    },
    // 16. Cloud Threats
    "cloud-threats": {
      name: "Cloud Threats",
      tips: [
        "Monitor AWS CloudTrail or Azure Activity logs for unauthorized IAM user creation or mass EC2 instance destruction.",
        "Look for log-ins from disabled or dormant cloud accounts."
      ],
      queries: [
        {
          name: "AWS Console Login Without MFA",
          query: "index=aws_cloudtrail eventName=\"ConsoleLogin\" responseElements.ConsoleLogin=\"Success\" additionalEventData.MFAUsed=\"No\"",
          type: "Detection"
        },
        {
          name: "Azure AD Suspicious Role Assignment",
          query: "index=azure_audit OperationName=\"Add member to role\" RoleName IN (\"Global Administrator\", \"Privileged Role Administrator\")",
          type: "Detection"
        }
      ]
    },
    // 17. Active Directory
    "active-directory": {
      name: "Active Directory",
      tips: [
        "Focus on Kerberos anomalies: Event 4769 with failure code 0x1B (Kerberoasting) or Event 4768 requesting RC4 (TGT stealing).",
        "Watch group membership changes in built-in admin groups (Event 4728, 4732, 4756)."
      ],
      queries: [
        {
          name: "Kerberoasting Indicator",
          query: "index=windows EventCode=4769 TicketOptions=\"0x40810000\" TicketEncryptionType=\"0x17\" | where TargetUserName!=\"$*\"",
          type: "Detection"
        },
        {
          name: "Domain Admin Group Member Added",
          query: "index=windows EventCode=4728 OR EventCode=4732 OR EventCode=4756 TargetUserName=\"Domain Admins\"",
          type: "Detection"
        }
      ]
    },
    // 18. Email Threats
    "email-threats": {
      name: "Email Threats",
      tips: [
        "Hunts focus on malicious sender domains, excessive forwarding rules, or large volumes of emails sent (account takeover).",
        "Monitor for phishing indicators like newly registered domains and mismatched Sender/From fields."
      ],
      queries: [
        {
          name: "Suspicious Inbox Forwarding Rule created",
          query: "index=o365 Operation=New-InboxRule Parameters{}.Name=ForwardTo | table UserId, Parameters{}.Value",
          type: "Detection"
        },
        {
          name: "High Volume External Emails (Account Takeover)",
          query: "index=email src_user=\"*@yourcompany.com\" dest_user!=\"*@yourcompany.com\" | stats count by src_user | where count > 500",
          type: "Hunting"
        }
      ]
    },
    // 19. Network Anomalies
    "network-anomalies": {
      name: "Network Anomalies",
      tips: [
        "Baseline internal traffic to identify abnormal subnet-to-subnet communications.",
        "Utilize Zeek/Suricata logs to identify non-standard protocols on standard ports."
      ],
      queries: [
        {
          name: "SSH Traffic on Non-Standard Port",
          query: "index=network sourcetype=zeek_conn proto=tcp service=ssh dest_port!=22",
          type: "Detection"
        },
        {
          name: "RDP Connection from External IP",
          query: "index=firewall dest_port=3389 direction=inbound | iplocation src_ip | search Country!=\"Internal\"",
          type: "Detection"
        }
      ]
    },
    // 20. Endpoint Anomalies
    "endpoint-anomalies": {
      name: "Endpoint Anomalies",
      tips: [
        "Detect abnormal host behavior like stopping EDR services or disabling Windows Defender.",
        "Find unusual binaries executing from user profile directories."
      ],
      queries: [
        {
          name: "Windows Defender Disabled via Reg",
          query: "index=windows EventCode=4688 CommandLine=\"*reg* add *DisableAntiSpyware* /t REG_DWORD /d 1*\"",
          type: "Detection"
        },
        {
          name: "Service Stopped",
          query: "index=windows EventCode=7036 Message=\"*entered the stopped state*\" ServiceName IN (\"*Sysmon*\",\"*Defender*\",\"*CrowdStrike*\")",
          type: "Detection"
        }
      ]
    },
    // 21. Linux / UNIX Threats
    "linux-threats": {
      name: "Linux / UNIX Threats",
      tips: [
        "Monitor auth.log for ssh brute forcing and syslogs for unauthorized su/sudo usage.",
        "Look for history file deletion (.bash_history) or cron job manipulation."
      ],
      queries: [
        {
          name: "SSH Brute Force",
          query: "index=linux sourcetype=syslog OR sourcetype=auth | search \"Failed password\" | stats count by src_ip, user | where count > 10",
          type: "Detection"
        },
        {
          name: "Bash History Deleted",
          query: "index=linux sourcetype=bash_history (command=\"*rm *.bash_history*\" OR command=\"*cat /dev/null > *.bash_history*\")",
          type: "Detection"
        }
      ]
    },
    // 22. Windows Specific
    "windows-specific": {
      name: "Windows Specific",
      tips: [
        "Hunt for LOLBins (Living off the Land Binaries) like certutil, mshta, bitsadmin being used to download payloads.",
        "Monitor WMI repository access and execution."
      ],
      queries: [
        {
          name: "Suspicious Certutil Download",
          query: "index=windows EventCode=4688 ProcessName=\"certutil.exe\" CommandLine=\"*-urlcache*\" CommandLine=\"*-split*\"",
          type: "Detection"
        },
        {
          name: "Suspicious Mshta Execution",
          query: "index=windows EventCode=4688 ProcessName=\"mshta.exe\" CommandLine=\"*http*\" OR CommandLine=\"*vbscript*\"",
          type: "Detection"
        }
      ]
    },
    // 23. Threat Hunting (Fallback or explicit category)
    "threat-hunting": {
      name: "Threat Hunting Operations",
      tips: [
        "Perform long-tail analysis to find outliers in process execution, network connections, or user agent strings.",
        "Look for mismatches in file metadata, e.g. a file named svchost.exe with missing Microsoft signatures."
      ],
      queries: [
        {
          name: "Rare Process Execution (Long-tail analysis)",
          query: "index=windows EventCode=4688 | rare limit=20 ProcessName",
          type: "Hunting"
        },
        {
          name: "Unusual HTTP User Agents",
          query: "index=proxy | stats count by http_user_agent | sort count asc | head 20",
          type: "Hunting"
        }
      ]
    }
  }
};

/**
 * Accessor function to get tips for a specific category.
 * Used dynamically by app.js rule detail view.
 */
function getSplunkTipsForCategory(categoryId) {
  return SPLUNK_INTELLIGENCE_DATA.categories[categoryId] || null;
}

// Make accessible to window
if (typeof window !== 'undefined') {
  window.SPLUNK_INTELLIGENCE_DATA = SPLUNK_INTELLIGENCE_DATA;
  window.getSplunkTipsForCategory = getSplunkTipsForCategory;
}
