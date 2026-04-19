$c = Get-Content "c:\Users\user\Desktop\siem ++\reference_repo.html" -Raw
$ids = [regex]::Matches($c, '\{id:')
Write-Host "Total queries: $($ids.Count)"
$cats = [regex]::Matches($c, 'cat:"([^"]+)"')
$g = @{}
foreach($x in $cats){
    $v = $x.Groups[1].Value
    if($g.ContainsKey($v)){$g[$v]++}else{$g[$v]=1}
}
foreach($k in ($g.Keys | Sort-Object)){
    Write-Host "$k : $($g[$k])"
}
