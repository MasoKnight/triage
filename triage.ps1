# --- Config ---
$out = "C:\Triage"
$timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$metaFile = "$out\metadata.txt"

# Ensure output directory
try {
    New-Item -Path $out -ItemType Directory -Force | Out-Null
    "Triage started at $timestamp" | Out-File $metaFile -Encoding UTF8
    "Host: $env:COMPUTERNAME" | Out-File $metaFile -Append -Encoding UTF8
    "User: $(whoami)" | Out-File $metaFile -Append -Encoding UTF8
} catch {
    Write-Error "Failed to create $out : $($_.Exception.Message)"
    exit 1
}

# Helper to write errors/notes
function Write-Note ($file, $text) {
    $text | Out-File -FilePath $file -Encoding UTF8
}

# --- Basic system info ---
try {
    whoami | Out-File "$out\whoami.txt"
    systeminfo | Out-File "$out\systeminfo.txt"
} catch {
    Write-Note "$out\systeminfo-error.txt" "Error collecting basic system info: $($_.Exception.Message)"
}

# --- Processes (with command line & parent) ---
try {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId,ParentProcessId,Name,CommandLine |
        Sort-Object ProcessId |
        Out-File "$out\processes.txt"
} catch {
    Write-Note "$out\processes-error.txt" "Error collecting processes: $($_.Exception.Message)"
}

# --- Services ---
try {
    Get-CimInstance Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,PathName |
        Out-File "$out\services.txt"
} catch {
    Write-Note "$out\services-error.txt" "Error collecting services: $($_.Exception.Message)"
}

# --- Scheduled Tasks ---
try {
    Get-ScheduledTask |
        Select TaskName,TaskPath,State,Author,Principal |
        Out-File "$out\scheduledtasks.txt"
} catch {
    Write-Note "$out\scheduledtasks-error.txt" "Error collecting scheduled tasks: $($_.Exception.Message)"
}

# --- Run keys / Startup ---
try {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run* ,HKCU:\Software\Microsoft\Windows\CurrentVersion\Run* -ErrorAction SilentlyContinue |
        Select PSPath,PSChildName,Value |
        Out-File "$out\runkeys.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,User | Out-File "$out\startup-commands.txt"
} catch {
    Write-Note "$out\runkeys-error.txt" "Error collecting startup/run keys: $($_.Exception.Message)"
}

# --- Network: listeners & established connections ---
try {
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Out-File "$out\net-listeners.txt"
} catch {
    Write-Note "$out\net-listeners-error.txt" "Error collecting listeners: $($_.Exception.Message)"
}

try {
    Get-NetTCPConnection -State Established |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Out-File "$out\net-established.txt"
} catch {
    Write-Note "$out\net-established-error.txt" "Error collecting established connections: $($_.Exception.Message)"
}

# --- Recent executables in user locations (7 days) ---
try {
    $cutoff=(Get-Date).AddDays(-7)
    Get-ChildItem $env:APPDATA,$env:LOCALAPPDATA,C:\ProgramData -Recurse -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $cutoff -and ($_.Extension -match 'exe|dll|ps1|bat|cmd|vbs') } |
        Select FullName,LastWriteTime |
        Out-File "$out\recent-user-exes.txt"
} catch {
    Write-Note "$out\recent-user-exes-error.txt" "Error searching recent user executables: $($_.Exception.Message)"
}

# --- Sample unsigned system drivers (quick) ---
try {
    Get-ChildItem C:\Windows\System32\drivers\*.sys -ErrorAction SilentlyContinue |
        Select-Object FullName,@{n='Signed';e={(Get-AuthenticodeSignature $_.FullName).Status}} |
        Where-Object { $_.Signed -ne 'Valid' } |
        Out-File "$out\drivers-unsigned-sample.txt"
} catch {
    Write-Note "$out\drivers-error.txt" "Error checking driver signatures: $($_.Exception.Message)"
}

# --- Process parent chain (simple listing) ---
try {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId,ParentProcessId,Name,CommandLine |
        Sort-Object ParentProcessId |
        Out-File "$out\process-parent-chain.txt"
} catch {
    Write-Note "$out\process-parent-chain-error.txt" "Error collecting parent chain: $($_.Exception.Message)"
}

# --- Local users & admins ---
try {
    Get-LocalUser | Select Name,Enabled,LastLogon,PasswordLastSet | Out-File "$out\localusers.txt"
    Get-LocalGroupMember -Group Administrators | Select Name,PrincipalSource | Out-File "$out\local-admins.txt"
} catch {
    Write-Note "$out\users-error.txt" "Error collecting local users/groups: $($_.Exception.Message)"
}

# --- Installed programs recently added (past 14 days) ---
try {
    $cutInstallDate = (Get-Date).AddDays(-14).ToString('yyyyMMdd')
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Select DisplayName,DisplayVersion,Publisher,InstallDate |
        Where-Object { $_.InstallDate -and $_.InstallDate -gt $cutInstallDate } |
        Out-File "$out\recent-installs.txt"
} catch {
    Write-Note "$out\recent-installs-error.txt" "Error collecting recent installs: $($_.Exception.Message)"
}

# --- Firewall rules (enabled) ---
try {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select Name,DisplayName,Direction,Action,Profile | Out-File "$out\firewall-enabled-rules.txt"
} catch {
    Write-Note "$out\firewall-error.txt" "Error collecting firewall rules: $($_.Exception.Message)"
}

# --- Event logs (guarded) ---
# Security log (4624 successful logon, 4625 failed) for past 7 days
try {
    $secFilter = @{LogName='Security'; Id=@(4624,4625); StartTime=(Get-Date).AddDays(-7)}
    $secEvents = Get-WinEvent -FilterHashtable $secFilter -MaxEvents 500 -ErrorAction Stop
    if ($secEvents -and $secEvents.Count -gt 0) {
        $secEvents | Out-File "$out\security-logons.txt"
    } else {
        Write-Note "$out\security-logons-note.txt" "No matching Security events found for IDs 4624/4625 in the last 7 days. (Query succeeded but returned no events.)"
    }
} catch {
    Write-Note "$out\security-logons-error.txt" "Error reading Security log: $($_.Exception.Message). Ensure script is running elevated and auditing is enabled."
}

# PowerShell Operational log (if present)
try {
    $psEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 300 -ErrorAction Stop
    if ($psEvents -and $psEvents.Count -gt 0) {
        $psEvents | Out-File "$out\powershell-oplog.txt"
    } else {
        Write-Note "$out\powershell-oplog-note.txt" "No events found in Microsoft-Windows-PowerShell/Operational (or log disabled)."
    }
} catch {
    Write-Note "$out\powershell-oplog-error.txt" "Error reading PowerShell Operational log: $($_.Exception.Message)"
}

# --- Optional short wevtutil sample (text) to capture if Get-WinEvent fails for large logs ---
try {
    wevtutil qe Security /c:100 /f:text | Out-File "$out\security-wevtutil-sample.txt"
} catch {
    Write-Note "$out\wevtutil-error.txt" "Error running wevtutil: $($_.Exception.Message)"
}

# --- PowerShell history (if PSReadLine or history exists) ---
try {
    if (Get-Command Get-PSReadlineHistory -ErrorAction SilentlyContinue) {
        Get-PSReadlineHistory -Count 1000 | Out-File "$out\psreadline-history.txt"
    } else {
        # Fallback: current session history
        Get-History | Out-File "$out\powershell-session-history.txt"
    }
} catch {
    Write-Note "$out\ps-history-error.txt" "Error collecting PS history: $($_.Exception.Message)"
}

# --- Final message and optional packaging ---
try {
    "Triage collection complete at $(Get-Date)" | Out-File "$out\complete.txt"
    # Optional: compress results - uncomment to create C:\Triage.zip
    # Try to compress only if Compress-Archive is available
    # Compress-Archive -Path "$out\*" -DestinationPath "C:\Triage_$timestamp.zip" -Force
} catch {
    Write-Note "$out\finalize-error.txt" "Error finalizing triage: $($_.Exception.Message)"
}
