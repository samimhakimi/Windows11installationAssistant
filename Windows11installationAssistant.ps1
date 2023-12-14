


$version = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')

if($version -NE "23H2")
{
    

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
 
# Main
 
 
 
 
 
try {
    # Declarations
    [string]$DownloadDir = 'C:\Temp\Windows_FU\packages'
    [string]$LogDir = 'C:\Temp\Windows_FU\Logs'
    [string]$LogFilePath = [string]::Format("{0}\{1}_{2}.log", $LogDir, "$(get-date -format `"yyyyMMdd_hhmmsstt`")", $MyInvocation.MyCommand.Name.Replace(".ps1", ""))
    [string]$Url = 'https://go.microsoft.com/fwlink/?linkid=2171764'
    [string]$UpdaterBinary = "$($DownloadDir)\Win11Upgrade.exe"
    [string]$UpdaterArguments = '/quietinstall /skipeula /auto upgrade /dynamicupdate enable/copylogs $LogDir'
    [System.Net.WebClient]$webClient = New-Object System.Net.WebClient
 
    # Here the music starts playing .. 
    Write-Log -Message ([string]::Format("Info: Script init - User: {0} Machine {1}", $env:USERNAME, $env:COMPUTERNAME))
    Write-Log -Message ([string]::Format("Current Windows Version: {0}", [System.Environment]::OSVersion.ToString()))
     
    # Check if script is running as admin and elevated  
    if (!(CheckIfElevated)) {
        Write-Log -Message "ERROR: Will terminate!"
        break
    }
 
    # Check if folders exis
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
        Write-Log "updating to windwos 11 H3................."
    }
    else {
        Write-Log -Message ([string]::Format("ERROR: File {0} does not exist!", $UpdaterBinary))
    }
}
catch {
    Write-Log -Message $_.Exception.Message 
    Write-Error $_.Exception.Message 
}


function Get-Processes {

    Get-Process windows11*
    Write-Host "Installation in progress.............."
}

Get-Processes


}

else {

    Write-Host "Windows is running latest version 23H2"
}

