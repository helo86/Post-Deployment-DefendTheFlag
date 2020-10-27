### Create folders and make shares
$path="C:\Shares"
if( -Not ( Test-Path -Path $path )){
    # file with path $path doesn't exist
	Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Creating Shared Folders..."
	New-Item "C:\Shares" –type directory

	New-Item "C:\Shares\Accounting and Finance" –type directory
	New-SMBShare -Name "Accounting and Finance" -Path "C:\Shares\Accounting and Finance" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Accounting and Finance"
	 
	New-Item "C:\Shares\Helpdesk" –type directory
	New-SMBShare -Name "Helpdesk" -Path "C:\Shares\Helpdesk" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Helpdesk"

	New-Item "C:\Shares\HR" –type directory
	New-SMBShare -Name "HR" -Path "C:\Shares\HR" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Human Resource Management"

	New-Item "C:\Shares\Management" –type directory
	New-SMBShare -Name "Management" -Path "C:\Shares\Management" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Management"

	New-Item "C:\Shares\Marketing" –type directory
	New-SMBShare -Name "Marketing" -Path "C:\Shares\Marketing" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Marketing"

	New-Item "C:\Shares\Purchasing" –type directory
	New-SMBShare -Name "Purchasing" -Path "C:\Shares\Purchasing" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Purchasing"

	New-Item "C:\Shares\Research and Development" –type directory
	New-SMBShare -Name "Research and Development" -Path "C:\Shares\Research and Development" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Research and Development"

	New-Item "C:\Shares\Sales" –type directory
	New-SMBShare -Name "Sales" -Path "C:\Shares\Sales" -FullAccess "contoso.azure\Domain Admins" -ChangeAccess "contoso.azure\Sales"
} else {

	Write-Host "'[{0:HH:mm}]' -f (Get-Date)) The Shares already exist"
}


