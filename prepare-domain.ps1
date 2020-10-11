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
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user printeradm with sensitive data in User Attributes" 
}
else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user $SAM already exists. Moving On."
}
 
###########################################################################
### 2. Password Spraying - User has start password set
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Users with start password of the domain"
if (!([ADSI]::Exists("LDAP://CN=NewAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "NewAdmin" -DisplayName "NewAdmin" -SamAccountName "newadm" -UserPrincipalName "newadm" -GivenName "Horst" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Start123!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user newadm with start password of the domain" 
}
else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user $SAM already exists. Moving On."
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
}
else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user DBAdmin already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://CN=WebAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "WebAdmin" -DisplayName "WebAdmin" -SamAccountName "webadm" -description "WebAdministrationAccount" -UserPrincipalName "webadm" -GivenName "Web" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Web1234!200" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:8080 contoso.azure\webadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User WebAdmin..." 
}
else
{
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user WebAdmin already exists. Moving On."
} 

if (!([ADSI]::Exists("LDAP://CN=IAMadmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "IAMadmin" -DisplayName "IAMadmin" -SamAccountName "iamadm" -description "IAMAdministrationAccount" -UserPrincipalName "iamadm" -GivenName "IAM" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "k3jdfiu2KAn3!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:445 contoso.azure\iamadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User IAMadmin..." 
}
else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user IAMadmin already exists. Moving On."
} 

if (!([ADSI]::Exists("LDAP://CN=SoundAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	
	New-ADUser -Name "SoundAdmin" -DisplayName "SoundAdmin" -SamAccountName "soundadm" -description "SoundAdministrationAccount" -UserPrincipalName "soundadm" -GivenName "Sound" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "k2k3kkksllaKLs!$" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:1337 contoso.azure\soundadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User SoundAdmin..." 
}
else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user SoundAdmin already exists. Moving On."
}

if (!([ADSI]::Exists("LDAP://CN=MercureAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	
	New-ADUser -Name "MercureAdmin" -DisplayName "MercureAdmin" -SamAccountName "mercureadm" -description "MercureAdministrationAccount" -UserPrincipalName "mercureadm" -GivenName "Mercure" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Mercure2020!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	setspn -s http/wef.contoso.azure:443 contoso.azure\mercureadm
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user Kerberoastable User MercureAdmin..." 
	
}
else
{
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) The user MercureAdmin already exists. Moving On."
}

###########################################################################
#### 4. ASREP Roasting - ASREP Roastable Users
###########################################################################
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding ASREP Roastable Users..."

if (!([ADSI]::Exists("LDAP://CN=MercureAdmin,OU=ServiceAccounts,OU=AdministrativeAccounts,DC=contoso,DC=azure")))
{
	
	New-ADUser -Name "TankAdmin" -DisplayName "TankAdmin" -SamAccountName "tankadm" -description "TankAdministrationAccount" -UserPrincipalName "tankadm" -GivenName "Tank" -Surname "Administrator" -AccountPassword ((ConvertTo-SecureString "Peaceful2020!" -AsPlainText -Force)) -Enabled $true -Path "OU=ServiceAccounts, OU=AdministrativeAccounts, DC=CONTOSO, DC=AZURE" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
	Get-ADUser tankadm | Set-ADAccountControl -DoesNotRequirePreAuth $true
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Created user ASREP Roastable User TankAdmin..." 
}
else
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
}
else
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

###########################################################################
### 8. Constrained Delegation
###########################################################################
