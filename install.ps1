# Web Server Administration - Test 1 script
# This script is meant to be run on a Windows Server 2012 machine

# Create a variable for the student number
$StudentNumber = "000855799"

# Pre-running steps:
#   Install google chrome
#   Install Nartac's IIS Crypto

# Check if the following tasks are scheduled and if they are end them
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

# Workflow to complete the lab
Import-Module PSWorkflow
workflow CompleteLab {
    function InitialSetup {
        # Elevate the PowerShell execution policy to (Bypass).
        Set-ExecutionPolicy -ExecutionPolicy Bypass
    
        # Rename the computer to WS000855799
        Rename-Computer -NewName "WS$StudentNumber"
    
        # Set the computers time zone to (Eastern Standard Time US & Canada)
        Set-TimeZone -Id "Eastern Standard Time"
    
        # Disable all firewall profiles
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    
        # Get the first InterfaceIndex of the network adapter
        $InterfaceIndex = Get-NetAdapter | Select-Object -First 1 | Select-Object -ExpandProperty InterfaceIndex
    
        # Set a static IP address of 192.168.100.20 and a static subnet mask of 255.255.255.0
        New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress 192.168.100.20 -PrefixLength 24 -AddressFamily IPv4
        Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled
    
        # Restart the computer
        Restart-Computer
    }
    
    function InstallRequirements {
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
            "Web-Mgmt-Service",
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
        Install-WindowsFeature -Name $Features -IncludeManagementTools
    }
    
    function PromoteToController {
        # Promote the server to a domain controller
        if (!(Get-WmiObject -Query "SELECT * FROM Win32_ComputerSystem" | where-object { $_.Domain -eq "d$StudentNumber.com" })) {
            Import-Module ADDSDeployment
            Install-ADDSDomainController `
                -InstallDns `
                -Credential (Get-Credential)`
                -DomainName ("d$StudentNumber.com") `
        
        }
    }
    
    function CreateWebsites {
        # Delete the default website if it exists
        Import-Module WebAdministration
        if (Get-WebSite | Where-Object { $_.Name -eq "Default Web Site" }) {
            Remove-WebSite -Name "Default Web Site"
        }
    
        # Create a array containing all the websites
        $Websites = @("sales.$StudentNumber.au", "www.$StudentNumber.co.uk", "donations.wildlife-$StudentNumber.org")
        $Ports = @("80", "443", "8080")
    
        # Create the websites in IIS
        Import-Module WebAdministration
        $j = 0
        $Websites.ForEach({
                New-WebSite -Name $_ -IPAddress "192.168.100.20" -Port $Ports[$j] -PhysicalPath "C:\Data\$_" -Force
            })
    
        # Create Dns records for the websites
        Import-Module DnsServer
        $i = 0
        $Websites.ForEach({
                Add-DnsServerResourceRecordA -ZoneName "d$StudentNumber.com" -Name $_ -IPv4Address "192.168.100.2$i"
                $i++
            })
        
        # Enable HSTS for the websites to make them secure
        $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
        $sitesCollection.foreach({
                Set-IISConfigAttributeValue -SectionPath "system.applicationHost/sites" -CollectionPath "sites/site[@name='$($_.Name)']" -AttributePath "hsts[@enabled='true']/@maxAge" -Value "31536000"
                Set-IISConfigAttributeValue -SectionPath "system.applicationHost/sites" -CollectionPath "sites/site[@name='$($_.Name)']" -AttributePath "hsts[@enabled='true']/@includeSubDomains" -Value "true"
                Set-IISConfigAttributeValue -SectionPath "system.applicationHost/sites" -CollectionPath "sites/site[@name='$($_.Name)']" -AttributePath "hsts[@enabled='true']/@redirectHttpToHttps" -Value "true"
                Set-IISConfigAttributeValue -SectionPath "system.applicationHost/sites" -CollectionPath "sites/site[@name='$($_.Name)']" -AttributePath "hsts[@enabled='true']/@preload" -Value "true"
                Set-IISConfigAttributeValue -SectionPath "system.applicationHost/sites" -CollectionPath "sites/site[@name='$($_.Name)']" -AttributePath "hsts[@enabled='true']/@confirm" -Value "true"
            })
    
        # Create the SAN/UC certificate:
        New-SelfSignedCertificate -DnsName "sales.$StudentNumber.au", "www.$StudentNumber.co.uk", "donations.wildlife-$StudentNumber.org" -CertStoreLocation cert:\LocalMachine\My -FriendlyName "SAN/UC Certificate"
    
        # Import the module for managing IIS
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Management") 
        [Microsoft.Web.Management.Server.ManagementAuthentication]::CreateUser("User1", "P@ssw0rd")
        [Microsoft.Web.Management.Server.ManagementAuthorization]::Grant("User1", "sales.$StudentNumber.au", $true)
    }

    "Performing initial setup..."
    InitialSetup

    "Installing requirements..."
    InstallRequirements

    "Promoting to a domain controller..."
    PromoteToController

    "Creating websites..."
    CreateWebsites
    Exit
}

$TaskName = "ResumeWorkflows"
$PS = $PSHOME + "\powershell.exe"
$Action = New-ScheduledTaskAction -Execute $PS -Argument " -executionpolicy bypass c:\resume.ps1"
$Trigger = New-ScheduledTaskTrigger -AtLogOn

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest
CompleteLab -AsJob -JobName $(get-date -Format hhmmss)
