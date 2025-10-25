# ==============================
# check-domaincomputers.ps1
# ==============================

# ---- handmatig instelbare variabelen ----
$Domain = "cowmotors.com"             # <-- pas dit aan naar het gewenste domein
$DomainController = "dc01.cowmotors.com"  # <-- pas dit aan naar de juiste DC
$Throttle = 60
$ResolveTimeoutMs = 1000

Write-Host "[INFO] Enumerating computers in $Domain via $DomainController`n"

# ---- controleer of PowerView of AD-module beschikbaar is ----
if (-not (Get-Command Get-DomainComputer -ErrorAction SilentlyContinue)) {
    if (Test-Path ".\PowerView.ps1") {
        . .\PowerView.ps1
    } elseif (Get-Module -ListAvailable ActiveDirectory) {
        Import-Module ActiveDirectory
        function Get-DomainComputer { 
            Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem |
                Select-Object Name, DNSHostName, OperatingSystem 
        }
    } else {
        Write-Error "PowerView of AD-module niet gevonden."; exit
    }
}

# ---- computers ophalen uit het gekozen domein ----
$computers = Get-DomainComputer -DomainController $DomainController -Domain $Domain |
             Select-Object Name, DNSHostName, OperatingSystem

# ---- parallel IP resolve ----
$scriptBlock = {
    param($dns, $timeoutMs)
    $obj = [PSCustomObject]@{ DNSHostName = $dns; IPAddress = $null }
    if ($dns) {
        try {
            $r = Resolve-DnsName -Name $dns -Type A -ErrorAction Stop
            if ($r) {
                $a = $r | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
                if ($a) { $obj.IPAddress = $a.IPAddress }
            }
            if (-not $obj.IPAddress) {
                $addr = ([System.Net.Dns]::GetHostAddresses($dns) |
                         Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                         Select-Object -First 1)
                if ($addr) { $obj.IPAddress = $addr.IPAddressToString }
            }
        } catch {}
    }
    return $obj
}

$pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
$pool.Open()
$jobs = @()

foreach ($c in $computers) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    $ps.AddScript($scriptBlock).AddArgument($c.DNSHostName).AddArgument($ResolveTimeoutMs) | Out-Null
    $async = $ps.BeginInvoke()
    $jobs += [PSCustomObject]@{ PS = $ps; Async = $async; Name = $c.Name; DNS = $c.DNSHostName; OS = $c.OperatingSystem }
}

$results = foreach ($j in $jobs) {
    $res = $j.PS.EndInvoke($j.Async)
    $j.PS.Dispose()
    $r = $res | Select-Object -First 1
    [PSCustomObject]@{
        Name        = $j.Name
        DNSHostName = $j.DNS
        IPAddress   = $r.IPAddress
        OS          = $j.OS
    }
}

$pool.Close(); $pool.Dispose()
$results | Format-Table -AutoSize
