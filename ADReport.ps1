[CmdletBinding()]
Param(
    [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
)

#Requires -Module ActiveDirectory,GroupPolicy

$AdParam = @{Server = $DomainName}


#region UserStats
$DisabledUser       = @(Search-ADAccount @AdParam -AccountDisabled -UsersOnly).Count
$ExpiredUser        = @(Search-ADAccount @AdParam -AccountExpired -UsersOnly).Count
$ExpiringUser       = @(Search-ADAccount @AdParam -AccountExpiring -UsersOnly).Count
$LockedUser         = @(Search-ADAccount @AdParam -LockedOut -UsersOnly).Count
$PwdExpiredUser     = @(Search-ADAccount @AdParam -PasswordExpired -UsersOnly).Count
$PwdNeverExpireUser = @(Search-ADAccount @AdParam -PasswordNeverExpires -UsersOnly).Count
$AdminUser          = @(Get-ADUser @AdParam -Filter {AdminCount -eq 1}).Count
$TotalUser          = @(Get-ADUser @AdParam -Filter *).Count

$UsersStats = @(
    [PSCustomObject]@{Label='DisabledUsers';Count=$DisabledUser;Percent=("{0:P2}" -f ($DisabledUser/$TotalUser))}
    [PSCustomObject]@{Label='ExpiredUser';Count=$ExpiredUser;Percent=("{0:P2}" -f ($ExpiredUser/$TotalUser))}
    [PSCustomObject]@{Label='ExpiringUser';Count=$ExpiringUser;Percent=("{0:P2}" -f ($ExpiringUser/$TotalUser))}
    [PSCustomObject]@{Label='LockedUser';Count=$LockedUser;Percent=("{0:P2}" -f ($LockedUser/$TotalUser))}
    [PSCustomObject]@{Label='PwdExpiredUser';Count=$PwdExpiredUser;Percent=("{0:P2}" -f ($PwdExpiredUser/$TotalUser))}
    [PSCustomObject]@{Label='PwdNeverExpireUser';Count=$PwdNeverExpireUser;Percent=("{0:P2}" -f ($PwdNeverExpireUser/$TotalUser))}
    [PSCustomObject]@{Label='AdminUser';Count=$AdminUser;Percent=("{0:P2}" -f ($AdminUser/$TotalUser))}
)
#endregion

#region ComputerStats
$DisabledComputer       = @(Search-ADAccount @AdParam -AccountDisabled -ComputersOnly).Count
#$ExpiredComputer        = @(Search-ADAccount @AdParam -AccountExpired -ComputersOnly).Count
#$ExpiringComputer       = @(Search-ADAccount @AdParam -AccountExpiring -ComputersOnly).Count
#$LockedComputer         = @(Search-ADAccount @AdParam -LockedOut -ComputersOnly).Count
#$PwdExpiredComputer     = @(Search-ADAccount @AdParam -PasswordExpired -ComputersOnly).Count
#$PwdNeverExpireComputer = @(Search-ADAccount @AdParam -PasswordNeverExpires -ComputersOnly).Count

$TotalComputerList = Get-ADComputer @AdParam -Filter * -Properties OperatingSystem
$TotalComputer = @($TotalComputerList).Count

$ComputerStats = @(
    [PSCustomObject]@{Label='DisabledComputers';Count=$DisabledComputer;Percent=("{0:P2}" -f ($DisabledComputer/$TotalComputer))}
    #[PSCustomObject]@{Label='ExpiredComputer';Count=$ExpiredComputer;Percent=("{0:P2}" -f ($ExpiredComputer/$TotalComputer))}
    #[PSCustomObject]@{Label='ExpiringComputer';Count=$ExpiringComputer;Percent=("{0:P2}" -f ($ExpiringComputer/$TotalComputer))}
    #[PSCustomObject]@{Label='LockedComputer';Count=$LockedComputer;Percent=("{0:P2}" -f ($LockedComputer/$TotalComputer))}
    #[PSCustomObject]@{Label='PwdExpiredComputer';Count=$PwdExpiredComputer;Percent=("{0:P2}" -f ($PwdExpiredComputer/$TotalComputer))}
    #[PSCustomObject]@{Label='PwdNeverExpireComputer';Count=$PwdNeverExpireComputer;Percent=("{0:P2}" -f ($PwdNeverExpireComputer/$TotalComputer))}
)
$ComputerOSStats = $TotalComputerList | Group-Object -Property OperatingSystem -NoElement | Sort-Object -Property Count -Descending | Select-Object Name,Count
#endregion

#region DCStats & list
$TotalDC    = @(Get-ADDomainController @AdParam -Filter *).Count
$TotalRODC  = @(Get-ADDomainController @AdParam -Filter {IsReadOnly -eq $true}).Count
$TotalRWDC  = @(Get-ADDomainController @AdParam -Filter {IsReadOnly -eq $false}).Count 

$DCStats = @(
    [PSCustomObject]@{Label='TotalRODC';Count=$TotalRODC;Percent=("{0:P2}" -f ($TotalRODC/$TotalDC))}
    [PSCustomObject]@{Label='TotalRWDC';Count=$TotalRWDC;Percent=("{0:P2}" -f ($TotalRWDC/$TotalDC))}
)

$DomainControllers = Get-ADDomainController @AdParam -Filter * | Select-Object -Property Name,IPv4Address,IsGlobalCatalog,IsReadOnly,OperatingSystem,Site
#endregion

#region GroupStats
$TotalGroup    = @(Get-ADGroup @AdParam -Filter *).Count
$AdminGroup  = @(Get-ADGroup @AdParam -Filter {AdminCount -eq 1}).Count

$GroupStats = @(
    [PSCustomObject]@{Label='AdminGroup';Count=$AdminGroup;Percent=("{0:P2}" -f ($AdminGroup/$TotalGroup))}
)
#endregion

#region GPOStats
$GPO  = Get-GPO -Domain $DomainName -All
$TotalGPO    = @($GPO).Count
$AllSettingsDisabledGPO = @($GPO | Where-Object -FilterScript {$_.GpoStatus -eq 'AllSettingsDisabled'}).Count
$EmptyGPO = @($GPO | Where-Object -FilterScript {$_.User.DSVersion -eq 0 -and $_.Computer.DSVersion -eq 0}).Count

$GPOStats = @(
    [PSCustomObject]@{Label='AllSettingsDisabledGPO';Count=$AllSettingsDisabledGPO;Percent=("{0:P2}" -f ($AllSettingsDisabledGPO/$TotalGPO))}
    [PSCustomObject]@{Label='EmptyGPO';Count=$EmptyGPO;Percent=("{0:P2}" -f ($EmptyGPO/$TotalGPO))}
)
#endregion

#region Site & Subnet
$Site  = Get-ADReplicationSite @AdParam -Filter * | Select-Object -Property Name,ManagedBy,InterSiteTopologyGenerator
$Subnet = Get-ADReplicationSubnet @AdParam -Filter * | Select-Object -Property Name, Location, Site
#endregion

#region HTML
@"
<!DOCTYPE html>
<html>
<head>
<style>
table {
    border-collapse: collapse;
}
h2 {text-align:center}
th, td {
    padding: 8px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

tr:hover{background-color:#f5f5f5}
</style>
</head>
<body>
<h1>Active Directory Report for $($DomainName).

<h2>Users, Computers & Groups:</h2>
<h3>Users: $TotalUser</h3>
$($UsersStats | ConvertTo-Html -Fragment)
<h3>Computers: $TotalComputer</h3>
$($ComputerStats | ConvertTo-Html -Fragment)
$($ComputerOSStats | ConvertTo-Html -Fragment)
<h3>Groups: $TotalGroup</h3>
$($GroupStats | ConvertTo-Html -Fragment)

<h2>Group Policies: $TotalGPO</h2>
$($GPOStats | ConvertTo-Html -Fragment)

<h2>Domain Controllers: $TotalDC</h2>
<h3>Statistics</h3>
$($DCStats | ConvertTo-Html -Fragment)
<h3>List</h3>
$($DomainControllers | ConvertTo-Html -Fragment)

<h2>Sites & Subnets:</h2>
<h3>Sites: $(@($Site).Count)</h3>
$($Site | ConvertTo-Html -Fragment)
<h3>Subnets: $(@($Subnet).Count)</h3>
$($Subnet | ConvertTo-Html -Fragment)

</body>
"@ | Out-File -Encoding utf8 ADReport.html
#endregion

Invoke-Item ADReport.html
