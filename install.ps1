# Web Server Administration - Test 1 script
# This script is meant to be run on a Windows Server 2012 machine

# Pre-running steps:
#   Install google chrome
#   Install Nartac's IIS Crypto

# Set the window title and error action preference
$Host.UI.RawUI.WindowTitle = "Test 1 script - Web Server Administration"
$ErrorActionPreference = "Stop"

# Check if the following tasks are scheduled:
#   ResumeWorkflows
#   CompleteLab
# and if they are end them
if (Get-ScheduledTask | Where-Object { $_.TaskName -eq "ResumeWorkflows" }) {
    Get-ScheduledTask -TaskName ResumeWorkflows | Unregister-ScheduledTask -Confirm:$false
}

if (Get-ScheduledTask | Where-Object { $_.TaskName -eq "CompleteLab" }) {
    Get-ScheduledTask -TaskName CompleteLab | Unregister-ScheduledTask -Confirm:$false
}

# Check if file "resume.ps1" exists in the root of the C: drive
if (!(Test-Path "C:\resume.ps1")) {
    New-Item -Path "C:\resume.ps1" -ItemType File -Value "Import-Module PSWorkflow`nGet-Job -State Suspended | Resume-Job -Wait | Wait-Job"
}

# Final setup workflow
Import-Module PSWorkflow
workflow CompleteLab {
    # Create a variable for the student number
    $StudentNumber = "000855799"

    # Elevate the PowerShell execution policy to (Bypass).
    Set-ExecutionPolicy -ExecutionPolicy Bypass

    # Rename the computer to WS000855799
    Rename-Computer -NewName "WS$StudentNumber"

    # Set the computers time zone to (Eastern Standard Time US & Canada)
    InlineScript {
        Invoke-Command -ScriptBlock {
            Set-TimeZone -Id "Eastern Standard Time"
        }
    }
    
    # Disable all firewall profiles
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Get the first InterfaceIndex of the network adapter
    $InterfaceIndex = Get-NetAdapter | Select-Object -First 1 | Select-Object -ExpandProperty InterfaceIndex

    # Set the network adapter to use a static IP address
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled

    # Set a static IP address of (192.168.100.20) and a static subnet mask of (255.255.255.0)
    Set-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress 192.168.100.20 -PrefixLength 24

    # Restart the computer
    Restart-Computer

    InlineScript {
        # An array containing all the required features
        $Features = @(
            "AD-Domain-Services", 
            "DNS", 
            "Web-Server", 
            "Web-WebServer", 
            "Web-Common-Http", 
            "Web-Default-Doc", 
            "Web-Dir-Browsing", 
            "Web-Http-Errors", 
            "Web-Static-Content",
            "Web-Health", 
            "Web-Http-Logging", 
            "Web-Performance", 
            "Web-Stat-Compression", 
            "Web-Security", 
            "Web-Filtering", 
            "Web-Basic-Auth", 
            "Web-Mgmt-Tools", 
            "Web-Mgmt-Console",
            "GPMC", 
            "RSAT", 
            "RSAT-Role-Tools", 
            "RSAT-AD-Tools", 
            "RSAT-AD-PowerShell", 
            "RSAT-ADDS", 
            "RSAT-AD-AdminCenter", 
            "RSAT-ADDS-Tools", 
            "RSAT-DNS-Server"
        )

        # Install the required features
        $Features.ForEach({
                Install-WindowsFeature -Name $_ -IncludeManagementTools
            })

        # Promote the server to a domain controller
        Install-ADDSForest `
            -DomainName "d$StudentNumber.com" `
            -DomainNetbiosName "D$StudentNumber" `
            -ForestMode "WinThreshold" `
            -DomainMode "WinThreshold" `
            -InstallDns:$true `
            -DatabasePath "C:\Windows\NTDS" `
            -LogPath "C:\Windows\NTDS" `
            -SysvolPath "C:\Windows\SYSVOL" `
            -Force:$true

        # Create the websites
        $Websites = @( "sales.$StudentNumber.au", "www.$StudentNumber.co.uk", "donations.wildlife-$StudentNumber.org")
        $Websites.ForEach({
                New-Item -Path "C:\Data\$_" -ItemType Directory
                New-Item -Path "C:\Data\$_\homepage.html" -ItemType File
            })

        # TODO: Add the rest of the steps.
    }
}

$TaskName = "ResumeWorkflows"
$PS = $PSHOME + "\powershell.exe"
$Action = New-ScheduledTaskAction -Execute $PS -Argument " -executionpolicy bypass c:\resume.ps1"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest

CompleteLab -AsJob -JobName $(get-date -Format hhmmss)
