$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userName = $currentUser.Name
$userGroups = $currentUser.Groups | ForEach-Object {
    $_.Translate([System.Security.Principal.NTAccount]).Value
}

Get-CimInstance -ClassName win32_service | ForEach-Object {
    $path = $_.PathName
    $serviceName = $_.Name
    $startMode = $_.StartMode

    # Binary pad opschonen
    if ($path -match '^"(.+?)"') {
        $path = $matches[1]
    } elseif ($path -match '^([^\s]+)') {
        $path = $matches[1]
    } else {
        $path = $null
    }

    if ($path -and (Test-Path $path)) {
        try {
            $acl = Get-Acl $path
            foreach ($entry in $acl.Access) {
                $id = $entry.IdentityReference.Value
                if ($id -eq $userName -or $userGroups -contains $id) {
                    if ($entry.FileSystemRights.ToString() -match 'FullControl|Modify') {
                        Write-Host "$serviceName`t$path`t$startMode"
                        break
                    }
                }
            }
        } catch {}
    }
}
