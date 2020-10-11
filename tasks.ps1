# Add tasks to simulate a living AD
# Example 
# From an elevated PowerShell console on VictimPC run the following code:

$action = New-ScheduledTaskAction -Execute 'cmd.exe'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$runAs = 'Contoso\RonHD'
$ronHHDPass = 'FightingTiger$'
Register-ScheduledTask -TaskName "RonHD Cmd.exe - AATP SA Playbook" -Trigger $trigger -User $runAs -Password $ronHHDPass -Action $action

# Sign in to the machine as JeffL. The Cmd.exe process will start in context of RonHD after logon, simulating Helpdesk managing the machine.


# Simulate domain activities from AdminPC
while ($true)
{
    Invoke-Expression "dir \\ContosoDC\c$"
    Start-Sleep -Seconds 300
}
