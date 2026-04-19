# Add category tags to existing rules in parts 1-4
# Maps rule IDs to their appropriate attack categories

$categoryMap = @{
  # Part 1
  "SR-0001" = "email-threats"
  "SR-0002" = "email-threats"
  "SR-0003" = "web-attacks"
  "SR-0004" = "brute-force"
  "SR-0005" = "insider-threat"
  "SR-0006" = "execution"
  "SR-0007" = "execution"
  "SR-0008" = "execution"
  "SR-0009" = "persistence"
  "SR-0010" = "execution"
  "SR-0011" = "persistence"
  "SR-0012" = "persistence"
  "SR-0013" = "persistence"
  "SR-0014" = "persistence"
  "SR-0015" = "persistence"
  "SR-0016" = "privilege-escalation"
  "SR-0017" = "privilege-escalation"
  "SR-0018" = "privilege-escalation"
  "SR-0019" = "privilege-escalation"
  "SR-0020" = "defense-evasion"
  "SR-0021" = "defense-evasion"
  "SR-0022" = "defense-evasion"
  "SR-0023" = "defense-evasion"
  "SR-0024" = "defense-evasion"
  "SR-0025" = "defense-evasion"
  # Part 2
  "SR-0026" = "brute-force"
  "SR-0027" = "credential-access"
  "SR-0028" = "active-directory"
  "SR-0029" = "active-directory"
  "SR-0030" = "credential-access"
  "SR-0031" = "active-directory"
  "SR-0032" = "reconnaissance"
  "SR-0033" = "reconnaissance"
  "SR-0034" = "reconnaissance"
  "SR-0035" = "reconnaissance"
  "SR-0036" = "lateral-movement"
  "SR-0037" = "lateral-movement"
  "SR-0038" = "lateral-movement"
  "SR-0039" = "lateral-movement"
  "SR-0040" = "lateral-movement"
  "SR-0041" = "collection"
  "SR-0042" = "collection"
  "SR-0043" = "collection"
  "SR-0044" = "network-anomalies"
  "SR-0045" = "windows-specific"
  "SR-0046" = "endpoint-anomalies"
  "SR-0047" = "network-anomalies"
  "SR-0048" = "data-exfiltration"
  "SR-0049" = "data-exfiltration"
  "SR-0050" = "data-exfiltration"
  "SR-0051" = "ransomware"
  "SR-0052" = "ransomware"
  "SR-0053" = "ransomware"
  "SR-0054" = "execution"
  "SR-0055" = "ransomware"
  # Part 3
  "SR-0056" = "defense-evasion"
  "SR-0057" = "defense-evasion"
  "SR-0058" = "defense-evasion"
  "SR-0059" = "credential-access"
  "SR-0060" = "credential-access"
  "SR-0061" = "lateral-movement"
  "SR-0062" = "lateral-movement"
  "SR-0063" = "network-anomalies"
  "SR-0064" = "network-anomalies"
  "SR-0065" = "email-threats"
  "SR-0066" = "data-exfiltration"
  "SR-0067" = "lateral-movement"
  "SR-0068" = "defense-evasion"
  "SR-0069" = "credential-access"
  "SR-0070" = "data-exfiltration"
  # Part 4
  "SR-0071" = "defense-evasion"
  "SR-0072" = "active-directory"
  "SR-0073" = "persistence"
  "SR-0074" = "cloud-threats"
  "SR-0075" = "execution"
  "SR-0076" = "windows-specific"
  "SR-0077" = "active-directory"
  "SR-0078" = "endpoint-anomalies"
  "SR-0079" = "defense-evasion"
  "SR-0080" = "collection"
}

$files = @(
  "js\sigma-rules-part1.js",
  "js\sigma-rules-part2.js",
  "js\sigma-rules-part3.js",
  "js\sigma-rules-part4.js"
)

$totalUpdated = 0
foreach ($file in $files) {
  $path = Join-Path $PSScriptRoot $file
  $content = Get-Content $path -Raw
  $updatedCount = 0
  
  foreach ($ruleId in $categoryMap.Keys) {
    $cat = $categoryMap[$ruleId]
    # Pattern: match "id: 'SR-XXXX', title: '...'" line and add category after the next line containing "author:"
    $pattern = "(id: '$ruleId',.*?author: '[^']+', date: '[^']+', modified: '[^']+',"
    $replacement = "`$1`n  category: '$cat',"
    
    if ($content -match [regex]::Escape("id: '$ruleId'")) {
      # Find the line with id and add category after the modified field on same line
      $oldPattern = "id: '$ruleId', title: '([^']+)',`r?`n  status: '([^']+)', severity: '([^']+)', author: '([^']+)', date: '([^']+)', modified: '([^']+)',"
      $newContent = "id: '$ruleId', title: '`$1',`n  status: '`$2', severity: '`$3', author: '`$4', date: '`$5', modified: '`$6',`n  category: '$cat',"
      
      $before = $content.Length
      $content = $content -replace $oldPattern, $newContent
      if ($content.Length -ne $before) {
        $updatedCount++
      }
    }
  }
  
  if ($updatedCount -gt 0) {
    Set-Content $path -Value $content -NoNewline
    Write-Host "Updated $file - $updatedCount rules tagged"
    $totalUpdated += $updatedCount
  }
}

Write-Host "`nTotal rules updated with categories: $totalUpdated"
