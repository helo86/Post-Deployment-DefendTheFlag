Import-Module ActiveDirectory
# Purpose: Sets up the Server and Workstations OUs

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Checking AD services status"
$svcs = "adws","dns","kdc","netlogon"
Get-Service -name $svcs -ComputerName localhost | Select Machinename,Name,Status

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Server and Workstation OUs"

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Servers OU"
if (!([ADSI]::Exists("LDAP://OU=Servers,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Servers"
}
else
{
    Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Servers OU already exists. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Workstations OU"
if (!([ADSI]::Exists("LDAP://OU=Workstations,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Workstations"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Workstations OU already exists. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating UserAccounts OU"
if (!([ADSI]::Exists("LDAP://OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "UserAccounts"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) UserAccounts OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=US,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "US" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) US OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=France,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "France" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) France OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Brazil,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Brazil" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Brazil OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Canada,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Canada" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Canada OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Germany,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Germany" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Germany OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Australia,OU=UserAccounts,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Australia" -Path "OU=UserAccounts, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Australia OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Groups,DC=contoso,DC=azure")))
{
  New-ADOrganizationalUnit -Name "Groups" -Path "DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Groups OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=Global,OU=Groups,DC=contoso,DC=azure")))
{
	New-ADOrganizationalUnit -Name "Global" -Path "OU=Groups, DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) Global OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADOrganizationalUnit -Name "AdministrativeAccounts"  -Path "DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) AdministrativeAccounts OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADOrganizationalUnit -Name "ServiceAccounts"  -Path "OU=AdministrativeAccounts,DC=contoso, DC=azure"
}
else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) ServiceAccounts OU already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://OU=LocalAdminAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADOrganizationalUnit -Name "LocalAdminAccounts"  -Path "OU=AdministrativeAccounts,DC=contoso, DC=azure"
}else
{
  Write-Host "'[{0:HH:mm}]' -f (Get-Date)) LocalAdminAccounts OU already exists. Moving On."
}
