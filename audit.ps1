# This system audit script is created by dieter [at] secudea [dot] be

# Convert Wua History ResultCode to a Name # 0, and 5 are not used for history # See https://msdn.microsoft.com/en-us/library/windows/desktop/aa387095(v=vs.85).aspx
# Copy from https://www.thewindowsclub.com/check-windows-update-history-using-powershell

function Convert-WuaResultCodeToName
{
param( [Parameter(Mandatory=$true)]
[int] $ResultCode
)
$Result = $ResultCode
switch($ResultCode)
{
2
{
$Result = "Succeeded"
}
3
{
$Result = "Succeeded With Errors"
}
4
{
$Result = "Failed"
}
}
return $Result
}
function Get-WuaHistory
{
# Get a WUA Session
$session = (New-Object -ComObject 'Microsoft.Update.Session')
# Query the latest 1000 History starting with the first recordp
$history = $session.QueryHistory("",0,1000) | ForEach-Object {
$Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
# Make the properties hidden in com properties visible.
$_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
$Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
$_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
Write-Output $_
}
#Remove null records and only return the fields we want
$history |
Where-Object {![String]::IsNullOrWhiteSpace($_.title)} |
Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}

$dir="audit_$env:computername"
mkdir $dir 
$path = Resolve-Path $dir
$logfile = "log-$env:computername.txt"
echo "Creation of directories successfull: $dir`n" | Set-content -Path $path\$logfile

echo "Backup of local group policies`n" | Add-Content -Path $path\$logfile
./LGPO /b "$path"

echo "Exporting Security Settings`n" | Add-Content -Path $path\$logfile
secedit /export /cfg $path\security_$env:computername.inf /log $path\security_$env:computername.log

echo "Getting system information`n" | Add-Content -Path $path\$logfile
echo "Computer: $env:computername" | Add-Content -Path $path\$logfile
date | Add-Content -Path $path\$logfile
echo "User: $env:USERNAME\$env:USERDOMAIN`n" | Add-Content -Path $path\$logfile

echo "Extracting systeminfo`n" | Add-Content -Path $path\$logfile
systeminfo > $path\systeminfo-$env:computername.txt
echo "Get Computer Information`n" | Add-Content -Path $path\$logfile
Get-ComputerInfo | Out-File -FilePath $path\computer-info_$env:computername.txt -NoClobber

echo "Extracting installed applications`n" | Add-Content -Path $path\$logfile
Get-WmiObject Win32_product | select name,vendor,version | export-csv -delimiter "`t" -path $path\installed-software_$env:computername.txt -notype
Get-Package | select name,version,summary | export-csv -delimiter "`t" -path $path\installed-packages_$env:computername.txt -notype

echo "Extracting installed optional windows components`n" | Add-Content -Path $path\$logfile
Get-WindowsOptionalFeature -Online | select FeatureName,State | export-csv -delimiter "`t" -path $path\installed-optional-components_$env:computername.txt -notype

echo "Bios Information:`n" | Add-Content -Path $path\$logfile
Get-WmiObject -Class WIN32_BIOS | Add-Content -Path $path\$logfile

# checking if Windows update service is running, if not set it to manual temporarily to allow the script to extract patch information. Reset it to the previous state afterwards
$status = (Get-Service -Name wuauserv).StartType
if ($status = 'Disabled')
{
    Get-Service wuauserv | Set-Service -StartupType Manual -Status Running
}

echo "Extracting Installed patches`n" | Add-Content -Path $path\$logfile
Get-WuaHistory | select Result,Date,Title,Product | export-csv -delimiter "`t" -path $path\installed-patches_$env:computername.txt -notype
Get-HotFix | export-csv -delimiter "`t" -path $path\installed-hotfixes_$env:computername.txt -notype

# reset the windows update status
if ($status = 'Disabled')
{
    Get-Service wuauserv | Stop-Service -Force
    Get-Service wuauserv | Set-Service -StartupType Disabled
}

echo "Extracting running services with account names`n" | Add-Content -Path $path\$logfile
Get-WmiObject Win32_Service -filter 'State LIKE "Running"' | select DisplayName, StartName, StartMode, State | export-csv -delimiter "`t" -path $path\services_running_$env:computername.txt -notype

echo "Extracting all services with account names`n" | Add-Content -Path $path\$logfile
Get-WmiObject Win32_Service | select DisplayName, StartName, StartMode, State | export-csv -delimiter "`t" -path $path\services_all_$env:computername.txt -notype

echo "Extracting Local Users`n" | Add-Content -Path $path\$logfile
Get-LocalUser | export-csv -delimiter "`t" -path $path\local-users_$env:computername.txt -notype
echo "Extracting Local Groups`n" | Add-Content -Path $path\$logfile
Get-LocalGroup | export-csv -delimiter "`t" -path $path\local-groups_$env:computername.txt -notype
echo "Extracting Local Administrator Group Memberships`n" | Add-Content -Path $path\$logfile
Get-LocalGroupMember -Name Administrators | export-csv -delimiter "`t" -path $path\local-admin-group-membership_$env:computername.txt -notype

echo "Extracting scheduled tasks`n" | Add-Content -Path $path\$logfile
$schtask = schtasks.exe /query /s localhost  /V /FO CSV | ConvertFrom-Csv | Where { $_.TaskName -ne "TaskName" }
$schtask | where { $_.Author -ne "Microsoft Corporation" } | Select TaskName,"Task To Run","Run As User" | export-csv -delimiter "`t" -path $path\tasks_$env:computername.txt -notype

echo "Extracting shared folders`n" | Add-Content -Path $path\$logfile
Get-SmbShare | select Name,Path,Description | export-csv -delimiter "`t" -path $path\shares_$env:computername.txt -notype

echo "Extracting running processes`n" | Add-Content -Path $path\$logfile
Get-Process -IncludeUserName | select ProcessName,UserName,Path | export-csv -delimiter "`t" -path $path\process-list_$env:computername.txt -notype

echo "Getting network settings`n" | Add-Content -Path $path\$logfile

Get-NetIPConfiguration | Select-object InterfaceDescription -ExpandProperty AllIPAddresses | export-csv -delimiter "`t" -path $path\net-adapters_$env:computername.txt -notype
Get-NetIPAddress | Sort InterfaceIndex | export-csv -delimiter "`t" -path $path\net-ipaddresses_$env:computername.txt -notype
Get-NetRoute -Protocol Local | export-csv -delimiter "`t" -path $path\net-routes_$env:computername.txt -notype
Get-NetAdapterBinding | select InterfaceAlias,Description,ENABLED | export-csv -delimiter "`t" -path $path\net-adapterBindings_$env:computername.txt -notype

echo "Extracting Local Firewall settings `n" | Add-Content -Path $path\$logfile
Get-NetFirewallProfile  | export-csv -delimiter "`t" -path $path\fw-profile-local_$env:computername.txt -notype
Get-NetFirewallRule | export-csv -delimiter "`t" -path $path\fw-rules-local_$env:computername.txt -notype
netsh advfirewall export $path\fw-export-local.wfw

echo "Extracting Active Firewall settings `n" | Add-Content -Path $path\$logfile
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

echo "Extracting Autorun information`n"  | Add-Content -Path $path\$logfile
.\autorunsc.exe -ct -o $path\autoruns_$env:computername.txt

echo "Extracting GPO Result information`n" | Add-Content -Path $path\$logfile
gpresult.exe /H $path\gpresult_$env:computername.html
gpresult.exe /X $path\gpresult_$env:computername.xml

echo "saving registry for further analysis`n" | Add-Content -Path $path\$logfile
reg save hklm\system $path\system.sav
reg save hklm\security $path\security.sav
reg save hklm\sam $path\sam.sav
reg export hklm $path\hklm.reg

$compress = @{
Path= "$path\*.sav", "$path\hklm.reg"
CompressionLevel = "Fastest"
DestinationPath = "$path\reg.zip"
}
Compress-Archive @compress
Remove-Item "$path\*.sav"
Remove-Item "$path\hklm.reg"

echo "All data has been extracted"
