# Sensitive Information stored within the AD

1.) Start ADExplorer and search through the AD for sensitive information

PS> adexplorer.exe

ADexplorer> search user description field contains pw, pwd, password, pass

2.) Enumerate the AD with ADRecon

PS> .\ADRecon.ps1
