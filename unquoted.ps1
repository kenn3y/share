$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$username = $currentUser.Name
$userGroups = $currentUser.Groups | ForEach-Object {
    $_.Translate([System.Security.Principal.NTAccount]).Value
}

$writeRights = @(
    'FullControl',
    'Modify',
    'Write',
    'WriteData',
    'WriteAttributes',
    'WriteExtendedAttributes'
)

# Alleen relevante services
$services = Get-CimInstance -ClassName Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notlike "C:\Windows\*" -and
    $_.PathName -notmatch '^"'
}

foreach ($svc in $services) {
    $serviceName = $svc.Name
    $rawPath = $svc.PathName.Trim()

    # Haal pad naar .exe (excl. parameters)
    $exeMatch = [regex]::Match($rawPath, '^[^\"]*?\.exe', 'IgnoreCase')
    if (-not $exeMatch.Success) { continue }

    $exePath = $exeMatch.Value.Trim()
    if ($exePath -notmatch ' ') { continue }

    # Genereer juiste exploiteerbare .exe-paden (zoals Windows het interpreteert)
    $injectPaths = @()
    $parts = $exePath -split '\\'
    $build = $parts[0]  # Begin met "C:"
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $build += "\" + $parts[$i]
        if ($parts[$i] -match ' ') {
            $firstWord = $parts[$i] -split ' ' | Select-Object -First 1
            $injectPath = "$build"
            $injectPath = $injectPath.Substring(0, $injectPath.LastIndexOf('\')) + "\" + $firstWord + ".exe"
            $injectPaths += $injectPath
        }
    }

    # Controleer of je op een van die paden een payload kunt plaatsen
    foreach ($inject in $injectPaths) {
        $parent = Split-Path $inject -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path $parent)) {
            try {
                $acl = Get-Acl $parent
                foreach ($entry in $acl.Access) {
                    $id = $entry.IdentityReference.Value
                    if ($id -eq $username -or $userGroups -contains $id) {
                        foreach ($right in $writeRights) {
                            if ($entry.FileSystemRights.ToString() -match $right) {
                                Write-Host "$serviceName`t$exePath`tDROP HERE: $inject (writable)"
                                break
                            }
                        }
                    }
                }
            } catch {}
        }
    }
}
