<#
.SYNOPSIS
Displays the list of services created with this app
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$Delete,
    [Parameter(Mandatory=$false)]
    [switch]$OpenRegEdit    
)

#Requires -Version 4
Set-StrictMode -Version 'Latest'

$ErrorActionPreference = 'Stop'

$regexe='C:\Programs\SystemTools\reged.exe'
$List = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*')

ForEach($entry in $List){
    if($entry -eq $Null) {continue;}
    try{
        $im = $entry.InstallModule
    }catch{
        $im = $Null
    }
    
    if($im -eq $Null) {continue;}
	
	$PSPath = $entry.PSPath
    
	$imLen = $im.Length
	if($imLen -gt 0)
	{
		$PSPathLen = $PSPath.Length
		if($PSPathLen -gt 40){
			$PSPath = $PSPath.SubString(36)
            $PSPath = $PSPath.Replace('HKEY_LOCAL_MACHINE','HKLM:')
		}

        if(-not(Test-Path $PSPath)){
            Write-Host "[INVALID PATH] " -n -f DarkGreen; Write-Host "$PSPath" -f DarkGray
            continue;
        }
		

        if($OpenRegEdit){
            Set-Clipboard -Value "$PSPath"
            &"$regexe"
        }

        $DisplayName = (Get-ItemProperty  $PSPath).DisplayName
        Write-Host "[FOUND] " -n -f DarkGreen; Write-Host "Service '$DisplayName'" -f DarkGray

        $ParamsPath = Join-Path $PSPath 'Parameters'
		$DllPath = (Get-ItemProperty  $ParamsPath).ServiceDll

        if($Delete){
            Write-Host "Dll $DllPath`n=================>`t`t" -f DarkYellow; Write-Host "[DELETE] " -n -f DarkRed
            Remove-Item $DllPath -Force -ErrorAction Ignore
            Write-Host "Reg path $PSPath`n=================>`t`t" -f DarkYellow; Write-Host "[DELETE] " -n -f DarkRed; 
            Remove-Item $PSPath -Force -Recurse -ErrorAction Ignore
        }else{
            Write-Host "   Dll $DllPath" -f DarkYellow;
            Write-Host "   Reg path $PSPath" -f DarkYellow;
        }

	}
}
