# Declare Functions and Variables@
# Process name to check
$BLinfo = Get-Bitlockervolume
$processName = "win11*"

    # Declarations
    [string]$DownloadDir = 'C:\Temp\Windows_FU\packages'
    [string]$LogDir = 'C:\Temp\Windows_FU\Logs'
    [string]$LogFilePath = [string]::Format("{0}\{1}_{2}.log", $LogDir, "$(get-date -format `"yyyyMMdd_hhmmsstt`")", $MyInvocation.MyCommand.Name.Replace(".ps1", ""))
    [string]$Url = 'https://go.microsoft.com/fwlink/?linkid=2171764'
    [string]$UpdaterBinary = "$($DownloadDir)\Win11Upgrade.exe"

    

function Write-Log { 
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory)] 
        [string]$Message
    ) 
      
    try { 
        if (!(Test-Path -path ([System.IO.Path]::GetDirectoryName($LogFilePath)))) {
            New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($LogFilePath))
        }
        $DateTime = Get-Date -Format ‘yyyy-MM-dd HH:mm:ss’ 
        Add-Content -Value "$DateTime - $Message" -Path $LogFilePath
    } 
    catch { 
        Write-Error $_.Exception.Message 
    } 
}

# Checking if the script is running as an Admin
Function CheckIfElevated() {
    Write-Log "Info: Checking for elevated permissions..."
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "ERROR: Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
        return $false
    }
    else {
        Write-Log "Info: Code is running as administrator — go on executing the script..."
        return $true
    }
}


# Check if the machine needs Reboot.
function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    }
    catch { Write-Host "Error!" }

    return $false
}



$TestPending = Test-PendingReboot
$version = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')

 
 if($version -NE "23H2")
{
    
    try {


    # quietinstall: This argument typically instructs the installer to run in “quiet” mode, meaning it won’t display any user interface while installing.
    # /skipeula: This argument is often used to skip the display of the End User License Agreement (EULA) during installation.
    # /auto upgrade: This argument could be instructing the installer to automatically upgrade the software if an older version is detected.
    # /dynamicupdate enable: This argument might be used to enable dynamic updates during the installation process.
    # /copylogs $LogDir: This argument instructs the installer to copy log files to the directory specified by the $LogDir variable. 

    [string]$UpdaterArguments = '/quietinstall /skipeula /auto upgrade /dynamicupdate enable/copylogs $LogDir'
    [System.Net.WebClient]$webClient = New-Object System.Net.WebClient
 
    # Writing Logs here ......
    Write-Log -Message ([string]::Format("Info: Script init - User Logged in: {0} Machine Asset Number {1}", $env:USERNAME, $env:COMPUTERNAME))
    Write-Log -Message ([string]::Format("Machine needs reboot:", $TestPending))
    Write-Log -Message "Windows current feature update is: " 
    Write-Log -Message (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
    Write-Log -Message ([string]::Format("Current Windows Version: {0}", [System.Environment]::OSVersion.ToString()))

     
    # Check if script is running as admin and elevated  
    if (!(CheckIfElevated)) {
        Write-Log -Message "ERROR: Please run the script as an Admin! Process terminated!"
        break
    }
 
    # Check if folders exist if not create 
    if (!(Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir
    }
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir
    }
    if (Test-Path $UpdaterBinary) {
        Remove-Item -Path $UpdaterBinary -Force
    }
    # Download the Windows Update Assistant
    Write-Log -Message "Will try to download Windows Update Assistant.."
    $webClient.DownloadFile($Url, $UpdaterBinary)
 
    # If the Update Assistant exists -> create a process with argument to initialize the update process
    if (Test-Path $UpdaterBinary) {
        Start-Process -FilePath $UpdaterBinary -ArgumentList $UpdaterArguments -Wait
        Write-Log "Upgrading OS to Windwos 11 23H2..."
    }
    else {
        Write-Log -Message ([string]::Format("ERROR: File {0} does not exist!", $UpdaterBinary))
    }
}
catch {
    Write-Log -Message $_.Exception.Message 
    Write-Error $_.Exception.Message 
}

}

 

else 
{
    Write-Log -Message "Operating System has already up to date."
    Write-Log -Message (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
    Write-Log -Message ([string]::Format("Current Windows Version: {0}", [System.Environment]::OSVersion.ToString()))
}
