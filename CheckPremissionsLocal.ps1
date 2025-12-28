[CmdletBinding()]
param()

$choice = Read-Host "Do you want to check a (U)ser or a (G)roup? [U/G]"
switch -regex ($choice) {
    '^[Gg]$' { $principalType = 'Group' }
    '^[Uu]$' { $principalType = 'User' }
    default  {
        Write-Error "Invalid choice. Please run the script again and choose U or G."
        return
    }
}


$principalName = Read-Host "Enter LOCAL $principalType name (e.g. user12345 or MyLocalGroup)"
if ([string]::IsNullOrWhiteSpace($principalName)) {
    Write-Error "No name entered. Please run the script again and enter a LOCAL $principalType name."
    return
}

$ComputerName = $env:COMPUTERNAME


if ($principalType -eq 'User') {
    try {
        $localUser = Get-LocalUser -Name $principalName -ErrorAction Stop
    }
    catch {
        Write-Error "Could not find local USER '$principalName' on $ComputerName. Error: $_"
        return
    }
}
elseif ($principalType -eq 'Group') {
    try {
        $localGroup = Get-LocalGroup -Name $principalName -ErrorAction Stop
    }
    catch {
        Write-Error "Could not find local GROUP '$principalName' on $ComputerName. Error: $_"
        return
    }
}
else {
    Write-Error "Unexpected principal type"
    return
}


$RootPath = Read-Host "Enter folder path (local or UNC, e.g. D:\Shares or \\server\share)"
if (-not (Test-Path $RootPath)) {
    Write-Error "Path '$RootPath' does not exist."
    return
}


$SelectedAccount = $null

if ($principalType -eq 'User') {
    Write-Host "Resolving local group membership for user '$principalName' on ${ComputerName} ..." -ForegroundColor Cyan
    $userAccount = "$ComputerName\$principalName"
    $candidates = @()
    $candidates += $userAccount

    
    $localGroups = Get-LocalGroup -ErrorAction Stop
    foreach ($grp in $localGroups) {
        try {
            $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction Stop
        } catch {
            continue
        }
        if ($members.Name -contains $userAccount) {
            $candidates += "$ComputerName\$($grp.Name)"
        }
    }

    Write-Host ""
    Write-Host "User '$principalName' is a member of the following local accounts/groups on ${ComputerName}:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $candidates[$i])
    }

    
    $selectedIndex = $null
    while ($null -eq $selectedIndex) {
        $input = Read-Host "Enter the NUMBER of the account/group whose permissions you want to check"
        [int]$n = 0
        if (-not [int]::TryParse($input, [ref]$n)) {
            Write-Host "Please enter a valid number." -ForegroundColor Yellow
            continue
        }
        if ($n -lt 1 -or $n -gt $candidates.Count) {
            Write-Host "Number out of range. Choose between 1 and $($candidates.Count)." -ForegroundColor Yellow
            continue
        }
        $selectedIndex = $n - 1
    }

    $SelectedAccount = $candidates[$selectedIndex]
    Write-Host "You selected: $SelectedAccount" -ForegroundColor Green
}
elseif ($principalType -eq 'Group') {
    
    $SelectedAccount = "$ComputerName\$principalName"
    Write-Host "Checking permissions for local group '$SelectedAccount' ..." -ForegroundColor Cyan
}
else {
    Write-Error "Unexpected principal type"
    return
}


$Targets = @($SelectedAccount)

Write-Host ""
Write-Host "Scanning folders under $RootPath for permissions of '$SelectedAccount' ..." -ForegroundColor Yellow


function Get-SimpleLevel {
    param([System.Security.AccessControl.FileSystemRights]$Rights)

    if ($Rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) { return "FullControl" }
    if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Modify)      { return "Modify" }
    if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Write)       { return "Write" }
    if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Read -or
        $Rights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -or
        $Rights -band [System.Security.AccessControl.FileSystemRights]::ReadData)    { return "Read" }
	
    return "None"
}


$Results = @()
$Folders = Get-ChildItem $RootPath -Directory -Recurse -ErrorAction SilentlyContinue
$Folders = @($Folders) + (Get-Item $RootPath)

$counter = 0
foreach ($Folder in $Folders) {
    $counter++
    if ($counter % 100 -eq 0) {
        Write-Host "Processed $counter folders..." -ForegroundColor DarkGray
    }

    try {
        $ACL = Get-Acl -Path $Folder.FullName
    }
    catch {
        continue
    }

    $CombinedRights = [System.Security.AccessControl.FileSystemRights]0

   
    foreach ($ACE in $ACL.Access) {
        if ($ACE.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
            if ($Targets -contains $ACE.IdentityReference.Value) {
                $CombinedRights = $CombinedRights -bor $ACE.FileSystemRights
            }
        }
    }

   
    $Level = Get-SimpleLevel -Rights $CombinedRights

    if ($Level -ne "None") {
        $Results += [PSCustomObject]@{
            FolderPath      = $Folder.FullName
            PermissionLevel = $Level
            AccessType      = "Allow"
			Rights		    = $CombinedRights
			UserName	    = $principalName
			MemberOf        = $SelectedAccount
        }
    }
}


if (-not $Results) {
    Write-Host "`nNo permissions found for '$SelectedAccount' under $RootPath." -ForegroundColor Red
}
else {
    Write-Host "`n=== PERMISSIONS FOUND FOR '$SelectedAccount' ===" -ForegroundColor Green
    $Results | Sort-Object FolderPath | Format-Table -AutoSize

    $export = Read-Host "Export result to CSV? (Y/N)"
    if ($export -match '^[Yy]') {
        $safeName = $SelectedAccount -replace '[\\/:*?""<>|]', '_'
        $defaultPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\${ComputerName}_${safeName}_LocalPermissions.csv"
        $csvPath = Read-Host "Enter CSV path or press Enter for default [$defaultPath]"
        if ([string]::IsNullOrWhiteSpace($csvPath)) {
            $csvPath = $defaultPath
        }

        try {
            $Results | Sort-Object FolderPath | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $csvPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV: $_"
        }
    }
}
