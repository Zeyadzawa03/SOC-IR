// ══════════════════════════════════════════════════════════════
// Sigma-to-SIEM Conversion Engine
// Converts Sigma YAML detection logic → Splunk SPL / QRadar AQL
// ══════════════════════════════════════════════════════════════

const SigmaConverter = (() => {

  // ─── Field Mappings ───────────────────────────────────────
  const FIELD_MAP_SPLUNK = {
    // Process
    'Image': 'process_name', 'image': 'process_name',
    'OriginalFileName': 'OriginalFileName',
    'CommandLine': 'process', 'commandline': 'process',
    'ParentImage': 'parent_process_name', 'parentimage': 'parent_process_name',
    'ParentCommandLine': 'parent_process',
    'User': 'user', 'user': 'user',
    'IntegrityLevel': 'IntegrityLevel',
    'ProcessId': 'process_id',
    'ParentProcessId': 'parent_process_id',
    'CurrentDirectory': 'process_current_directory',
    // Network
    'DestinationIp': 'dest_ip', 'destinationip': 'dest_ip',
    'DestinationPort': 'dest_port', 'destinationport': 'dest_port',
    'SourceIp': 'src_ip', 'sourceip': 'src_ip', 'IpAddress': 'src_ip',
    'SourcePort': 'src_port', 'sourceport': 'src_port',
    'DestinationHostname': 'dest', 'destinationhostname': 'dest',
    'Protocol': 'protocol',
    // Auth
    'TargetUserName': 'Account_Name', 'targetusername': 'Account_Name',
    'SubjectUserName': 'SubjectUserName',
    'LogonType': 'LogonType', 'logontype': 'LogonType',
    'AuthenticationPackageName': 'AuthenticationPackageName',
    'TargetServerName': 'TargetServerName',
    'TargetDomainName': 'TargetDomainName',
    'Status': 'Status', 'SubStatus': 'SubStatus',
    // File
    'TargetFilename': 'file_name', 'targetfilename': 'file_name',
    'TargetObject': 'object_path', 'targetobject': 'object_path',
    'ImageLoaded': 'ImageLoaded', 'imageloaded': 'ImageLoaded',
    // Registry
    'Details': 'registry_value_data',
    // Event
    'EventID': 'EventCode', 'eventid': 'EventCode', 'EventCode': 'EventCode',
    'EventType': 'EventType', 'eventtype': 'EventType',
    // Sysmon specific
    'Hashes': 'Hashes', 'hashes': 'Hashes',
    'QueryName': 'query', 'queryname': 'query',
    'PipeName': 'PipeName', 'pipename': 'PipeName',
    // Service
    'ServiceName': 'service_name', 'servicename': 'service_name',
    'ServiceFileName': 'ImagePath',
    // Generic
    'ComputerName': 'ComputerName', 'computername': 'ComputerName',
    'GrantedAccess': 'GrantedAccess',
    'SourceImage': 'SourceImage',
    'TargetImage': 'TargetImage',
    'CallTrace': 'CallTrace',
    'PrivilegeList': 'PrivilegeList',
    'TicketEncryptionType': 'TicketEncryptionType',
    'TicketOptions': 'TicketOptions'
  };

  const FIELD_MAP_QRADAR = {
    'Image': 'Filename', 'image': 'Filename',
    'OriginalFileName': 'Filename',
    'CommandLine': 'Command', 'commandline': 'Command',
    'ParentImage': '"Parent Process Path"', 'parentimage': '"Parent Process Path"',
    'ParentCommandLine': '"Parent Command"',
    'User': 'username', 'user': 'username',
    'DestinationIp': 'destinationip', 'destinationip': 'destinationip',
    'DestinationPort': 'destinationport', 'destinationport': 'destinationport',
    'SourceIp': 'sourceip', 'sourceip': 'sourceip', 'IpAddress': 'sourceip',
    'SourcePort': 'sourceport', 'sourceport': 'sourceport',
    'DestinationHostname': 'Hostname',
    'TargetUserName': 'username', 'targetusername': 'username',
    'SubjectUserName': 'username',
    'LogonType': '"Logon Type"', 'logontype': '"Logon Type"',
    'TargetServerName': '"Target Server"',
    'TargetDomainName': '"Domain"',
    'TargetFilename': '"File Path"', 'targetfilename': '"File Path"',
    'TargetObject': '"Object Name"', 'targetobject': '"Object Name"',
    'ImageLoaded': '"Image Loaded"',
    'EventID': 'EventID', 'eventid': 'EventID', 'EventCode': 'EventID',
    'ServiceName': '"Service Name"', 'servicename': '"Service Name"',
    'ComputerName': '"Machine Identifier"',
    'QueryName': '"DNS Request Domain"', 'queryname': '"DNS Request Domain"',
    'PipeName': '"Pipe Name"',
    'GrantedAccess': '"Granted Access"',
    'SourceImage': '"Source Process"',
    'TargetImage': '"Target Process"',
    'Status': 'Status',
    'Protocol': '"Network Protocol"',
    'Hashes': 'Hash',
    'PrivilegeList': '"Privileges"',
    'TicketEncryptionType': '"Encryption Type"'
  };

  // ─── Log Source Mapping ─────────────────────────────────────
  const LOGSOURCE_SPLUNK = {
    'windows/security': 'index=wineventlog sourcetype=WinEventLog:Security',
    'windows/system': 'index=wineventlog sourcetype=WinEventLog:System',
    'windows/sysmon': 'index=wineventlog sourcetype=WinEventLog:Sysmon',
    'windows/powershell': 'index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational',
    'windows/process_creation': 'index=wineventlog (sourcetype=WinEventLog:Security EventCode=4688) OR (sourcetype=WinEventLog:Sysmon EventCode=1)',
    'windows/image_load': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=7',
    'windows/file_event': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11',
    'windows/registry_event': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=13',
    'windows/network_connection': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=3',
    'windows/dns_query': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=22',
    'windows/pipe_created': 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=17',
    'windows/wmi_event': 'index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)',
    'linux/process_creation': 'index=linux sourcetype=linux:audit type=EXECVE',
    'linux/syslog': 'index=linux sourcetype=syslog',
    'linux/auth': 'index=linux_secure sourcetype=linux_secure',
    'webserver/access': 'index=web sourcetype=access_combined',
    'firewall': 'index=firewall sourcetype=firewall',
    'proxy': 'index=proxy sourcetype=proxy',
    'dns': 'index=dns sourcetype=dns',
    'cloud/azure': 'index=azure sourcetype=azure:aad:signin OR sourcetype=azure:audit',
    'cloud/aws': 'index=aws sourcetype=aws:cloudtrail',
    'cloud/gcp': 'index=gcp sourcetype=google:gcp:pubsub:message',
    'email': 'index=email sourcetype=ms:o365:management',
    'default': 'index=main'
  };

  const LOGSOURCE_QRADAR = {
    'windows/security': "LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'",
    'windows/system': "LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Event Log'",
    'windows/sysmon': "LOGSOURCETYPENAME(devicetype) = 'Microsoft Sysmon'",
    'windows/powershell': "LOGSOURCETYPENAME(devicetype) ILIKE '%PowerShell%'",
    'windows/process_creation': "CATEGORYNAME(highlevelcategory) = 'System' AND CATEGORYNAME(category) ILIKE '%Process%Create%'",
    'windows/image_load': "QIDNAME(qid) ILIKE '%Image Loaded%'",
    'windows/file_event': "CATEGORYNAME(category) ILIKE '%File%'",
    'windows/registry_event': "CATEGORYNAME(category) ILIKE '%Registry%'",
    'windows/network_connection': "CATEGORYNAME(highlevelcategory) = 'Network'",
    'windows/dns_query': "CATEGORYNAME(category) ILIKE '%DNS%Query%'",
    'windows/wmi_event': "QIDNAME(qid) ILIKE '%WMI%'",
    'linux/process_creation': "LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%' AND CATEGORYNAME(category) ILIKE '%Process%'",
    'linux/syslog': "LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'",
    'linux/auth': "LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%' AND CATEGORYNAME(highlevelcategory) = 'Authentication'",
    'webserver/access': "LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%'",
    'firewall': "CATEGORYNAME(highlevelcategory) = 'Firewall'",
    'proxy': "CATEGORYNAME(highlevelcategory) = 'Proxy'",
    'dns': "CATEGORYNAME(category) ILIKE '%DNS%'",
    'cloud/azure': "LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'",
    'cloud/aws': "LOGSOURCETYPENAME(devicetype) ILIKE '%AWS%CloudTrail%'",
    'cloud/gcp': "LOGSOURCETYPENAME(devicetype) ILIKE '%GCP%'",
    'email': "LOGSOURCETYPENAME(devicetype) ILIKE '%Office 365%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%Exchange%'",
    'default': ''
  };

  // ─── Helpers ────────────────────────────────────────────────
  function resolveLogSourceKey(logsource) {
    if (!logsource) return 'default';
    const parts = [];
    if (logsource.product) parts.push(logsource.product.toLowerCase());
    if (logsource.service) parts.push(logsource.service.toLowerCase());
    if (logsource.category) parts.push(logsource.category.toLowerCase().replace(/ /g, '_'));
    // Try product/service first, then product/category
    let key = parts.join('/');
    if (LOGSOURCE_SPLUNK[key]) return key;
    // Try product alone
    if (logsource.product && LOGSOURCE_SPLUNK[logsource.product.toLowerCase()]) {
      return logsource.product.toLowerCase();
    }
    // Try category-based matching
    if (logsource.category) {
      const cat = logsource.category.toLowerCase().replace(/ /g, '_');
      const prodCat = (logsource.product ? logsource.product.toLowerCase() + '/' : '') + cat;
      if (LOGSOURCE_SPLUNK[prodCat]) return prodCat;
    }
    return 'default';
  }

  function mapFieldSplunk(f) { return FIELD_MAP_SPLUNK[f] || FIELD_MAP_SPLUNK[f.toLowerCase()] || f; }
  function mapFieldQRadar(f) { return FIELD_MAP_QRADAR[f] || FIELD_MAP_QRADAR[f.toLowerCase()] || f; }

  // ─── Parse Sigma YAML detection block ───────────────────────
  function parseSigmaYaml(yamlStr) {
    const result = { selections: {}, filters: {}, condition: '', logsource: {} };
    if (!yamlStr) return result;

    const lines = yamlStr.split('\n');
    let currentBlock = null;
    let currentKey = null;
    let inDetection = false;
    let inLogsource = false;
    let indent = 0;

    for (const line of lines) {
      const trimmed = line.trimEnd();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const lineIndent = line.search(/\S/);

      if (trimmed.startsWith('logsource:')) { inLogsource = true; inDetection = false; continue; }
      if (trimmed.startsWith('detection:')) { inDetection = true; inLogsource = false; continue; }
      if (trimmed.startsWith('condition:') && inDetection) {
        result.condition = trimmed.replace('condition:', '').trim();
        continue;
      }
      if (/^(title|id|status|description|author|date|modified|falsepositives|level|tags|references):/.test(trimmed) && lineIndent === 0) {
        inDetection = false; inLogsource = false; continue;
      }

      if (inLogsource && lineIndent > 0) {
        const m = trimmed.match(/^\s*(\w+):\s*(.+)/);
        if (m) result.logsource[m[1]] = m[2].trim();
      }

      if (inDetection && lineIndent > 0 && !trimmed.startsWith('condition:')) {
        // Selection/filter block header
        const blockMatch = trimmed.match(/^\s{4}(\w[\w_]*):\s*$/);
        if (blockMatch) {
          currentBlock = blockMatch[1];
          result.selections[currentBlock] = {};
          continue;
        }
        // Field with value or modifier
        const fieldMatch = trimmed.match(/^\s{8}(\S+?):\s*(.+)?$/);
        if (fieldMatch && currentBlock) {
          currentKey = fieldMatch[1];
          const val = fieldMatch[2];
          if (val && val !== '') {
            if (!result.selections[currentBlock]) result.selections[currentBlock] = {};
            if (!result.selections[currentBlock][currentKey]) result.selections[currentBlock][currentKey] = [];
            result.selections[currentBlock][currentKey].push(val.replace(/^['"]|['"]$/g, ''));
          }
          continue;
        }
        // List items
        const listMatch = trimmed.match(/^\s{12,}- ['"]?(.+?)['"]?\s*$/);
        if (listMatch && currentBlock && currentKey) {
          if (!result.selections[currentBlock]) result.selections[currentBlock] = {};
          if (!result.selections[currentBlock][currentKey]) result.selections[currentBlock][currentKey] = [];
          result.selections[currentBlock][currentKey].push(listMatch[1]);
          continue;
        }
      }
    }
    return result;
  }

  // ─── Build Splunk SPL from parsed detection ──────────────────
  function buildSplunkCondition(field, values, modifier) {
    const splunkField = mapFieldSplunk(field.split('|')[0]);
    const mod = modifier || '';
    const parts = [];

    for (const v of values) {
      const val = v.replace(/\\\\/g, '\\');
      if (mod.includes('endswith')) {
        parts.push(`${splunkField}="*${val}"`);
      } else if (mod.includes('startswith')) {
        parts.push(`${splunkField}="${val}*"`);
      } else if (mod.includes('contains')) {
        parts.push(`${splunkField}="*${val}*"`);
      } else if (mod.includes('re')) {
        parts.push(`match(${splunkField},"${val}")`);
      } else {
        parts.push(`${splunkField}="${val}"`);
      }
    }
    return parts.length === 1 ? parts[0] : '(' + parts.join(' OR ') + ')';
  }

  function buildQRadarCondition(field, values, modifier) {
    const qrField = mapFieldQRadar(field.split('|')[0]);
    const mod = modifier || '';
    const parts = [];

    for (const v of values) {
      const val = v.replace(/\\\\/g, '\\');
      if (mod.includes('endswith')) {
        parts.push(`${qrField} ILIKE '%${val}'`);
      } else if (mod.includes('startswith')) {
        parts.push(`${qrField} ILIKE '${val}%'`);
      } else if (mod.includes('contains')) {
        parts.push(`${qrField} ILIKE '%${val}%'`);
      } else if (mod.includes('re')) {
        parts.push(`${qrField} MATCHES '${val}'`);
      } else {
        const numVal = Number(v);
        if (!isNaN(numVal) && v.match(/^\d+$/)) {
          parts.push(`${qrField} = ${numVal}`);
        } else {
          parts.push(`${qrField} = '${val}'`);
        }
      }
    }
    return parts.length === 1 ? parts[0] : '(' + parts.join(' OR ') + ')';
  }

  function selectionToSplunk(selBlock) {
    const conditions = [];
    for (const [rawField, values] of Object.entries(selBlock)) {
      const pipeIdx = rawField.indexOf('|');
      const modifier = pipeIdx > -1 ? rawField.substring(pipeIdx + 1) : '';
      conditions.push(buildSplunkCondition(rawField, Array.isArray(values) ? values : [values], modifier));
    }
    return conditions.join('\n  ');
  }

  function selectionToQRadar(selBlock) {
    const conditions = [];
    for (const [rawField, values] of Object.entries(selBlock)) {
      const pipeIdx = rawField.indexOf('|');
      const modifier = pipeIdx > -1 ? rawField.substring(pipeIdx + 1) : '';
      conditions.push(buildQRadarCondition(rawField, Array.isArray(values) ? values : [values], modifier));
    }
    return conditions.join('\n  AND ');
  }

  // ─── Main Conversion Functions ──────────────────────────────

  function toSplunk(rule) {
    // If the rule has a pre-built Splunk query, use it enhanced
    if (rule.splunkQuery) return rule.splunkQuery;

    const parsed = parseSigmaYaml(rule.sigmaYaml);
    const lsKey = resolveLogSourceKey(rule.logsource || parsed.logsource);
    const base = LOGSOURCE_SPLUNK[lsKey] || LOGSOURCE_SPLUNK['default'];

    let query = base + '\n';

    // Build selection blocks
    const selNames = Object.keys(parsed.selections);
    if (selNames.length === 0) {
      // Fallback: extract key terms from the rule
      return buildFallbackSplunk(rule, base);
    }

    const selQueries = {};
    for (const name of selNames) {
      selQueries[name] = selectionToSplunk(parsed.selections[name]);
    }

    // Apply condition logic
    let condition = parsed.condition || selNames.join(' and ');
    let whereClause = condition;

    // Replace selection names with their queries
    for (const [name, q] of Object.entries(selQueries)) {
      const isNegated = condition.includes(`not ${name}`);
      if (isNegated) {
        whereClause = whereClause.replace(`not ${name}`, `NOT (${q})`);
      } else {
        whereClause = whereClause.replace(new RegExp(`\\b${name}\\b`, 'g'), `(${q})`);
      }
    }

    // Clean up condition
    whereClause = whereClause.replace(/\band\b/gi, ' AND ');
    whereClause = whereClause.replace(/\bor\b/gi, ' OR ');

    // Add EventCode filter if present in selections
    let eventCodeFilter = '';
    for (const sel of Object.values(parsed.selections)) {
      if (sel['EventID'] || sel['eventid'] || sel['EventCode']) {
        const ec = sel['EventID'] || sel['eventid'] || sel['EventCode'];
        eventCodeFilter = ` EventCode=${Array.isArray(ec) ? ec[0] : ec}`;
      }
    }
    if (eventCodeFilter) query = base + eventCodeFilter + '\n';

    query += `| where ${whereClause}\n`;
    query += `| stats count values(${mapFieldSplunk('ComputerName')}) as targets by ${mapFieldSplunk('User')}, _time\n`;
    query += `| where count > 0\n`;
    query += `| sort - count\n`;
    query += `| table _time, ${mapFieldSplunk('User')}, targets, count`;

    return query;
  }

  function toQRadar(rule) {
    // If the rule has a pre-built QRadar query, use it
    if (rule.qradarQuery) return rule.qradarQuery;

    const parsed = parseSigmaYaml(rule.sigmaYaml);
    const lsKey = resolveLogSourceKey(rule.logsource || parsed.logsource);
    const lsFilter = LOGSOURCE_QRADAR[lsKey] || '';

    let query = 'SELECT sourceip, destinationip, username,\n';
    query += '  QIDNAME(qid) as event_name,\n';
    query += '  COUNT(*) as event_count\n';
    query += 'FROM events\n';
    query += 'WHERE ';

    if (lsFilter) {
      query += lsFilter + '\n';
    }

    // Build selection blocks
    const selNames = Object.keys(parsed.selections);
    if (selNames.length === 0) {
      return buildFallbackQRadar(rule, lsFilter);
    }

    const selQueries = {};
    for (const name of selNames) {
      selQueries[name] = selectionToQRadar(parsed.selections[name]);
    }

    let condition = parsed.condition || selNames.join(' and ');

    // Build WHERE clause
    let hasSelection = false;
    for (const [name, q] of Object.entries(selQueries)) {
      const isNegated = condition.includes(`not ${name}`);
      const isFilter = name.startsWith('filter');
      if (isFilter || isNegated) {
        query += `  AND NOT (${q})\n`;
      } else {
        if (hasSelection) {
          const joiner = condition.includes(`${name}`) && condition.match(new RegExp(`\\bor\\s+${name}\\b`, 'i')) ? 'OR' : 'AND';
          query += `  ${joiner} (${q})\n`;
        } else {
          query += `  AND (${q})\n`;
          hasSelection = true;
        }
      }
    }

    query += 'GROUP BY sourceip, destinationip, username, qid\n';
    query += 'ORDER BY event_count DESC\n';
    query += 'LAST 24 HOURS';

    return query;
  }

  // ─── Fallback builders for rules without parseable YAML ─────
  function buildFallbackSplunk(rule, base) {
    let q = base + '\n';
    // Use technique & description keywords
    const keywords = [];
    if (rule.techniqueId) keywords.push(rule.techniqueId);
    if (rule.techniqueName) {
      const terms = rule.techniqueName.split(/[\s\/]+/).filter(t => t.length > 3);
      keywords.push(...terms.slice(0, 3));
    }
    if (keywords.length > 0) {
      q += `| search ${keywords.map(k => `"*${k}*"`).join(' OR ')}\n`;
    }
    q += `| stats count by user, src_ip, dest, _time\n`;
    q += `| sort - count\n`;
    q += `| table _time, user, src_ip, dest, count`;
    return q;
  }

  function buildFallbackQRadar(rule, lsFilter) {
    let q = 'SELECT sourceip, destinationip, username,\n';
    q += '  QIDNAME(qid) as event_name,\n';
    q += '  COUNT(*) as event_count\n';
    q += 'FROM events\n';
    q += 'WHERE ' + (lsFilter || '1=1') + '\n';
    if (rule.techniqueName) {
      const terms = rule.techniqueName.split(/[\s\/]+/).filter(t => t.length > 3);
      if (terms.length > 0) {
        q += `  AND (${terms.map(t => `eventname ILIKE '%${t}%'`).join(' OR ')})\n`;
      }
    }
    q += 'GROUP BY sourceip, destinationip, username, qid\n';
    q += 'ORDER BY event_count DESC\n';
    q += 'LAST 24 HOURS';
    return q;
  }

  // ─── Public API ──────────────────────────────────────────────
  return {
    toSplunk,
    toQRadar,
    mapFieldSplunk,
    mapFieldQRadar
  };

})();

// ─── Copy-to-clipboard utility ────────────────────────────────
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 2000);
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
  });
}
