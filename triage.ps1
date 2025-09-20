# triage.ps1 - collect triage outputs to C:\Triage
$out = "C:\Triage"
New-Item -Path $out -ItemType Directory -Force | Out-Null
whoami | Out-File "$out\whoami.txt"
systeminfo | Out-File "$out\systeminfo.txt"
# ... add the rest of your triage script here ...
Write-Host "Triage collection saved to $out"