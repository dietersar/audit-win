# This system audit script is created by dieter [at] secudea [dot] be

function ConvertTo-Hex
{
    Param([int]$Number)
    '0x{0:x}' -f $Number
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [switch]$FileOnly
    )

    # Write to the console unless FileOnly is specified
    if (-not $FileOnly) {
        Write-Host $Message
    }

    # Append to the log file
    try {
        Add-Content -Path $path\$logfile -Value $Message
    } catch {
        if (-not $FileOnly) {
            Write-Host "Failed to write to log file: $path\$logfile" -ForegroundColor Red
        }
    }
}

# Get the current working directory of the script
$currentDir = Get-Location

# Define the path to the wsusscn2.cab file in the current directory
$wsusCabPath = Join-Path $currentDir "wsusscn2.cab"

# Check if the wsusscn2.cab file exists in the current directory
if (-Not (Test-Path $wsusCabPath)) {
    Write-Log -Message "Error: wsusscn2.cab not found in the current directory: $currentDir" -ForegroundColor Red
	Write-Log -Message "Fetch the last wsusscn2.cab file from http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab and put it in the same directory" -ForegroundColor Red
    exit
}

$dir="audit_$env:computername"
if (-Not (Test-Path -Path $dir)) {
    mkdir $dir
}
$path = Resolve-Path $dir
$logfile = "log-$env:computername.txt"
Write-Log -Message "Creation of directories successfull: $dir"

Write-Log -Message "Backup of local group policies"
./LGPO /b "$path"

Write-Log -Message "Exporting Security Settings"
secedit /export /cfg $path\security_$env:computername.inf /log $path\security_$env:computername.log

Write-Log -Message "Getting system information"
Write-Log -Message "Computer: $env:computername" -FileOnly
date | Add-Content -Path $path\$logfile
Write-Log -Message "User: $env:USERNAME\$env:USERDOMAIN" -FileOnly

Write-Log -Message "Extracting systeminfo"
systeminfo > $path\systeminfo-$env:computername.txt
Write-Log -Message "Get Computer Information"
Get-ComputerInfo | Out-File -FilePath $path\computer-info_$env:computername.txt -NoClobber

Write-Log -Message "Extracting installed applications"
Get-WmiObject Win32_product | select name,vendor,version | export-csv -delimiter "`t" -path $path\installed-software_$env:computername.txt -notype
Get-Package | select name,version,summary | export-csv -delimiter "`t" -path $path\installed-packages_$env:computername.txt -notype

Write-Log -Message "Extracting installed optional windows components"
Get-WindowsOptionalFeature -Online | select FeatureName,State | export-csv -delimiter "`t" -path $path\installed-optional-components_$env:computername.txt -notype

Write-Log -Message "Extracting Bios Information"
Get-WmiObject -Class WIN32_BIOS | Add-Content -Path $path\$logfile

Write-Log -Message "Extracting missing patches..."

# Create the necessary COM objects for offline update searching
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$updateService = $updateServiceManager.AddScanPackageService("Offline Sync Service", $wsusCabPath, 1)
$updateSearcher = $updateSession.CreateUpdateSearcher()

# Set the server selection to "Others" (3)
$updateSearcher.ServerSelection = 3
$updateSearcher.ServiceID = $updateService.ServiceID

# Perform the search for missing updates
$searchResult = $updateSearcher.Search("IsInstalled=0")

# Get the list of updates from the search result
$updates = $searchResult.Updates

# Check if any updates were found
if ($updates.Count -eq 0) {
    Write-Log -Message "There are no applicable updates."
}
else
{
# Output the list of missing updates
Write-Log -Message "List of applicable items on the machine when using wsusscn2.cab:" -FileOnly

for ($i = 0; $i -lt $updates.Count; $i++) {
    $update = $updates.Item($i)
    Write-Log -Message "$($i + 1)> $($update.Title)" -FileOnly
}
}

Write-Log -Message "Extracting Installed hotfixes"
Get-HotFix | export-csv -delimiter "`t" -path $path\installed-hotfixes_$env:computername.txt -notype

Write-Log -Message "Extracting running services with account names"
Get-WmiObject Win32_Service -filter 'State LIKE "Running"' | select DisplayName, StartName, StartMode, State | export-csv -delimiter "`t" -path $path\services_running_$env:computername.txt -notype

Write-Log -Message "Extracting all services with account names"
Get-WmiObject Win32_Service | select DisplayName, StartName, StartMode, State | export-csv -delimiter "`t" -path $path\services_all_$env:computername.txt -notype

Write-Log -Message "Extracting Local Users"
Get-LocalUser | export-csv -delimiter "`t" -path $path\local-users_$env:computername.txt -notype
Write-Log -Message "Extracting Local Groups"
Get-LocalGroup | export-csv -delimiter "`t" -path $path\local-groups_$env:computername.txt -notype
Write-Log -Message "Extracting Local Administrator Group Memberships"
Get-LocalGroupMember -SID S-1-5-32-544 | export-csv -delimiter "`t" -path $path\local-admin-group-membership_$env:computername.txt -notype

Write-Log -Message "Extracting scheduled tasks"
$schtask = schtasks.exe /query /s localhost  /V /FO CSV | ConvertFrom-Csv | Where { $_.TaskName -ne "TaskName" }
$schtask | where { $_.Author -ne "Microsoft Corporation" } | Select TaskName,"Task To Run","Run As User" | export-csv -delimiter "`t" -path $path\tasks_$env:computername.txt -notype

Write-Log -Message "Extracting shared folders"
Get-SmbShare | select Name,Path,Description | export-csv -delimiter "`t" -path $path\shares_$env:computername.txt -notype

Write-Log -Message "Extracting running processes"
Get-Process -IncludeUserName | select ProcessName,UserName,Path | export-csv -delimiter "`t" -path $path\process-list_$env:computername.txt -notype

Write-Log -Message "Getting network settings"

Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | export-csv -delimiter "`t" -path $path\net-adapters_$env:computername.txt -notype
Get-NetIPAddress | Sort InterfaceIndex | export-csv -delimiter "`t" -path $path\net-ipaddresses_$env:computername.txt -notype
Get-NetRoute -Protocol Local | export-csv -delimiter "`t" -path $path\net-routes_$env:computername.txt -notype
Get-NetAdapterBinding | select InterfaceAlias,Description,ENABLED | export-csv -delimiter "`t" -path $path\net-adapterBindings_$env:computername.txt -notype

Write-Log -Message "Extracting Local Firewall settings "
Get-NetFirewallProfile  | export-csv -delimiter "`t" -path $path\fw-profile-local_$env:computername.txt -notype
Get-NetFirewallRule | export-csv -delimiter "`t" -path $path\fw-rules-local_$env:computername.txt -notype
netsh advfirewall export $path\fw-export-local.wfw

Write-Log -Message "Extracting Active Firewall settings "
Get-NetFirewallProfile -PolicyStore ActiveStore | export-csv -delimiter "`t" -path $path\fw-profile-active_$env:computername.txt -notype
Get-NetFirewallSetting -PolicyStore ActiveStore  | export-csv -delimiter "`t" -path $path\fw-settings-active_$env:computername.txt -notype
Get-NetFirewallRule -PolicyStore ActiveStore  | export-csv -delimiter "`t" -path $path\fw-rules-active_$env:computername.txt -notype

# code copied from https://stackoverflow.com/questions/44509183/powershell-get-nettcpconnection-script-that-also-shows-username-process-name
$obj=@()

Foreach($p In (Get-Process -IncludeUserName | where {$_.UserName} | `
  select Id, ProcessName, UserName)) {
      $properties = @{ 'PID'=$p.Id;
                       'ProcessName'=$p.ProcessName;
                       'UserName'=$p.UserName;
                     }
      $psobj = New-Object -TypeName psobject -Property $properties
      $obj+=$psobj
  }

Get-NetTCPConnection | where {$_.State -eq "Listen"} | select `
  LocalAddress, `
  LocalPort, `
  RemoteAddress, `
  RemotePort, `
  @{n="PID";e={$_.OwningProcess}}, @{n="ProcessName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty ProcessName)}}, `
  @{n="UserName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty UserName)}} |
  sort -Property ProcessName, UserName | export-csv -delimiter "`t" -path $path\net-listening_$env:computername.txt -notype

Write-Log -Message "Extracting Autorun information`n"  | Add-Content -Path $path\$logfile
.\autorunsc.exe -ct -o $path\autoruns_$env:computername.txt /accepteula

Write-Log -Message "Extracting GPO Result information"
gpresult.exe /H $path\gpresult_$env:computername.html
gpresult.exe /X $path\gpresult_$env:computername.xml

# Export of AV product status is based on Get-AVStatus.ps1 (https://gist.github.com/jdhitsolutions/1b9dfb31fef91f34c54b344c6516c30b)
Write-Log -Message "Extracting AntiVirus product information"
$results = @()
$AVProduct = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
foreach ($AV in $AVProduct)
{
    $state_hex = ConvertTo-Hex $AV.Productstate
    $mid = $state_hex.Substring(3,2)
    $end = $state_hex.Substring(5)
    if ($mid -match "00|01") { $Enabled = $False }
    else { $Enabled = $True }
    if ($end -eq "00") { $UpToDate = $True }
    else { $UpToDate = $False }
    $results += $AV | Select-Object Displayname, ProductState,
            @{Name = "Enabled"; Expression = { $Enabled } },
            @{Name = "UpToDate"; Expression = { $UptoDate } },
            @{Name = "Path"; Expression = { $_.pathToSignedProductExe } },
            Timestamp
}
$results | export-csv -delimiter "`t" -path $path\antivirus_$env:computername.txt -notype

Write-Log -Message "saving registry for further analysis"
reg save hklm\system $path\system.sav
reg save hklm\security $path\security.sav
reg save hklm\sam $path\sam.sav
reg export hklm $path\hklm.reg
# export tcp ip parameters for quicker analysis
reg export hklm\system\CurrentControlSet\Services\Tcpip\Parameters $path\tcpip_parameters.txt

$compress = @{
Path= "$path\*.sav", "$path\hklm.reg"
CompressionLevel = "Fastest"
DestinationPath = "$path\reg.zip"
}
Compress-Archive @compress
Remove-Item "$path\*.sav"
Remove-Item "$path\hklm.reg"

Write-Log -Message "Audit completed successfully. Output saved to $path." -ForegroundColor Green
