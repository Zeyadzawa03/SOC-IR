$html = Get-Content 'index.html' -Raw -Encoding UTF8

# 1. Inject Detection Testing nav item
$navOld = @'
      <div class="nav-section-label">Info</div>
'@
$navNew = @'
      <div class="nav-section-label">Quality Assurance</div>
      <div class="nav-item" data-page="detection-testing">
        <span class="nav-icon">&#129514;</span>
        Detection Testing
      </div>
      <div class="nav-section-label">Info</div>
'@
$html = $html.Replace($navOld.Trim(), $navNew.Trim())

# 2. Inject script tags after blue-team-pages.js
$scriptOld = '<script src="js/blue-team-pages.js"></script>'
$scriptNew = @'
<script src="js/blue-team-pages.js"></script>
<script src="js/detection-testing.js"></script>
<script src="js/detection-testing-page.js"></script>
'@
$html = $html.Replace($scriptOld, $scriptNew.Trim())

Set-Content 'index.html' -Value $html -Encoding UTF8
Write-Host 'SUCCESS: index.html patched' -ForegroundColor Green
