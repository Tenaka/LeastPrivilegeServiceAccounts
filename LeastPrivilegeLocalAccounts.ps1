<#
.Synopsis
Update a Windows Service that is using system to a non-priv user account
.Description
List the service account name and name of the Windows Service to be updated.
Create the User account and strip out Local User group so its not interactive, set a randomized password
Update the Service with account and password
Export and update User Rights Assignments for the Service Account to have 'Logon as a Service' right
.Version
#>

#List of Service Accounts (svc_) and the application the svc_ will run as a service
$svc1 = @{"svc_splunk" = "splunk"}
$svc2 = @{"svc_account2" = "Application2"}
$svc3 = @{"svc_account3" = "Application3"}

$svcUsers = $svc1, $svc2, $svc3

#Create Service Account, randomised password
#Find Windows Service and update to use Service account
foreach ($svcAcc in $svcUsers)
{
    #Svc Account
    $svcAccount = $svcAcc.Keys
   
    #Application Name
    $appName = $svcAcc.Values

    #Password length
    $length = 12

    #Number of random characters
    $random = 3

    #Creates complex random password for each svc account

    $assembly = Add-Type -AssemblyName system.web
    $randPass = [System.Web.Security.Membership]::GeneratePassword($length,$random)

    #Create svc account with randomized password and unable to change own password.

    net user $svcAccount $randPass /PASSWORDCHG:NO /ADD /YES

    #remove user group so its a service account and not able to interactively logon
    net localgroup users $svcAccount /DELETE

    #if account needs access to read security events, normally if service account event forwards to SIEM
    if ($svcAccount -eq "svc_splunk")
    {
        #add to eventlog users group to read security event logs
        net localgroup "Event Log Readers" $svcAccount /ADD
    }

    #sets password to never expire
    WMIC useraccount where "Name='$svcAccount'" SET PasswordExpires=FALSE

    #get the Windows Service based on the name of the listed App
    $svcName = gwmi Win32_service -Filter "name='$appName'"

    #Update Windows Service so the svc account and password replace system service
    $svcNAme.change($null,$null,$null,$null,$null,$false,".\$svcAccount",$randPass)

    }

#Hostname
$hn = hostname

#Create new folder to export security template to
$path = "C:\Logs\Services"
New-Item $path -ItemType Directory -Force 

#Export Security Settings inc User Rights Assignments with secedit.exe
secEdit.exe /export /cfg $path\currentTemplate.inf

#List the current user account SID's for 'Logon as a service'
$logonAsRight = Select-String $path\currentTemplate.inf -Pattern "SEServiceLogonRight"
$origSids = $logonAsRight.Line

#Create an empty Template 
Add-Content -Path $path\newTemplate.inf -Value '[Unicode]'
Add-Content -Path $path\newTemplate.inf -Value 'unicode=YES'
Add-Content -Path $path\newTemplate.inf -Value '[System Access]'
Add-Content -Path $path\newTemplate.inf -Value '[Event Audit]'
Add-Content -Path $path\newTemplate.inf -Value '[Registry Values]'
Add-Content -Path $path\newTemplate.inf -Value '[version]'
Add-Content -Path $path\newTemplate.inf -Value 'signature="$CHICAGO$"'
Add-Content -Path $path\newTemplate.inf -Value 'Revision=1'
Add-Content -Path $path\newTemplate.inf -Value '[Privilege Rights]'

#array for new service accounts and their sids
$svcSid=@()
foreach ($svcAcc in $svcUsers)

    {
        #Service Account
        $svcAcc = $svcAcc.Keys

        #Application Name for Service
        $appName = $svcAcc.Values

        #new object for each service account
        $objUser = New-Object System.Security.Principal.NTAccount("$hn\$svcAcc")
        $strSid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $svcSid += $strSid.Value 
    }

#take original sids and add to new list of sids
$sidOld =@()
$sidOld += $origSids

#combined list of sids
foreach ($svc in $svcSid)
    {
        $sidCombine += ",*$svc"
    }

#foreach sid add to the newTemplate.inf 
foreach ($sidIndi in $sidCombine)
    {
        Add-Content -Value $sidIndi -Path $path\newTemplate.inf -NoNewline
    }

#Run the SecEdit command to import the all accounts and add to Logon as a Service.
secedit.exe /configure /db $path\secEdit.sdb /cfg $path\newTemplate.inf /log $path\newTemplate.log
