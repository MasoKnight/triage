$out = "C:\Triage"
New-Item -Path $out -ItemType Directory -Force | Out-Null

# Basic system info
whoami | Out-File "$out\whoami.txt"
systeminfo | Out-File "$out\systeminfo.txt"

# Processes, services, tasks, startup, network
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine | Out-File "$out\processes.txt"
Get-CimInstance Win32_Service | Select Name,DisplayName,State,StartMode,PathName | Out-File "$out\services.txt"
Get-ScheduledTask | Select TaskName,TaskPath,State,Author,Principal | Out-File "$out\scheduledtasks.txt"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run* ,HKCU:\Software\Microsoft\Windows\CurrentVersion\Run* -ErrorAction SilentlyContinue | Out-File "$out\runkeys.txt"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Out-File "$out\listeners.txt"
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Out-File "$out\established-net.txt"

# Event logs (recent)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4624,4625);StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500 | Out-File "$out\security-logons.txt"
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 300 | Out-File "$out\powershell-oplog.txt"

# Users & groups
Get-LocalUser | Select Name,Enabled,LastLogon,PasswordLastSet | Out-File "$out\localusers.txt"
Get-LocalGroupMember -Group Administrators | Out-File "$out\local-admins.txt"

# Recent executables in user locations (7 days)
$cutoff=(Get-Date).AddDays(-7)
Get-ChildItem $env:APPDATA,$env:LOCALAPPDATA,C:\ProgramData -Recurse -ErrorAction SilentlyContinue |
Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $cutoff -and ($_.Extension -match 'exe|dll|ps1|bat|cmd|vbs') } |
Select FullName,LastWriteTime | Out-File "$out\recent-user-exes.txt"
