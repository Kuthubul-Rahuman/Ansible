#!powershell
# This file is part of Ansible

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy
#Requires -Module Ansible.ModuleUtils.FileUtil
#Requires -Module Ansible.ModuleUtils.SID

$ErrorActionPreference = "Stop"

$params = Parse-Args -arguments $args -supports_check_mode $true

$process_name_exact = Get-AnsibleParam -obj $params -name "process_name_exact" -type "list"
$process_name_pattern = Get-AnsibleParam -obj $params -name "process_name_pattern" -type "str"
$process_id = Get-AnsibleParam -obj $params -name "pid" -type "int" -default 0  # pid is a reserved variable in PowerShell, using process_id instead.
$owner = Get-AnsibleParam -obj $params -name "owner" -type "str"
$sleep = Get-AnsibleParam -obj $params -name "sleep" -type "int" -default 1
$pre_wait_delay = Get-AnsibleParam -obj $params -name "pre_wait_delay" -type "int" -default 0
$post_wait_delay = Get-AnsibleParam -obj $params -name "post_wait_delay" -type "int" -default 0
$process_min_count = Get-AnsibleParam -obj $params -name "process_min_count" -type "int" -default 1
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present"
$timeout = Get-AnsibleParam -obj $params -name "timeout" -type "int" -default 300

$result = @{
    changed = $false
    matched_processes = @()
}

# Validate the input
if ($state -eq "absent" -and $sleep -ne 1)
{
    Add-Warning -obj $result -message "sleep parameter has no effect when waiting for a process to stop."
}

if ($state -eq "absent" -and $process_min_count -ne 1)
{
    Add-Warning -obj $result -message "process_min_count parameter has no effect when waiting for a process to stop."
}

if (($process_name_exact -or $process_name_pattern) -and $process_id)
{
    Fail-json -obj $result -message "process_id may not be used with process_name_exact or process_name_pattern."
}
if ($process_name_exact -and $process_name_pattern)
{
    Fail-json -obj $result -message "process_name_exact and process_name_pattern may not be used at the same time."
}

if (-not ($process_name_exact -or $process_name_pattern -or $process_id -or $owner))
{
    Fail-json -obj $result -message "at least one of: process_name_exact, process_name_pattern, process_id, or owner must be supplied."
}

Function Get-ProcessMatchesFilter {
    [cmdletbinding()]
    Param(
        [String]
        $Owner,
        $ProcessNameExact,
        $ProcessNamePattern,
        [int]
        $ProcessId
    )

    $WMIProcesses = Get-Process -IncludeUserName
    foreach ($WMIProcess in $WMIProcesses) {

        # If a process name was specified in the filter, validate that here.
        if (-not [String]::IsNullOrEmpty($ProcessNamePattern)) {
            if ($WMIProcess.ProcessName -notmatch $ProcessNamePattern) {
                continue
            }
        }

        # If a process name was specified in the filter, validate that here.
        if ($ProcessNameExact -is [Array]) {
            if ($ProcessNameExact -notcontains $WMIProcess.ProcessName) {
                continue
            }
        } elseif (-not [String]::IsNullOrEmpty($ProcessNameExact)) {
            if ($ProcessNameExact -ne $WMIProcess.ProcessName) {
                continue
            }
        }

        # If a PID was specified in the filter, validate that here.
        if ($ProcessId -and $ProcessId -ne 0) {
            if ($ProcessId -ne $WMIProcess.Id) {
                continue
            }
        }

        # If an owner was specified in the filter, validate that here.
        if (-not [String]::IsNullOrEmpty($Owner)) {
            if ([String]::IsNullOrEmpty($WMIProcess.UserName)) {
                continue
            } elseif ((Convert-ToSID($Owner)) -ne (Convert-ToSID($WMIProcess.UserName))) {  # NOTE: This is rather expensive
                continue
            }
        }

        $WMIProcess | Select-Object -Property Id, ProcessName, UserName
    }
}

$module_start = Get-Date
Start-Sleep -Seconds $pre_wait_delay

if ($state -eq "present" ) {
    # Wait for a process to start
    $Processes = @()
    $attempts = 0
    Do {
        if (((Get-Date) - $module_start).TotalSeconds -gt $timeout) {
            $result.elapsed = ((Get-Date) - $module_start).TotalSeconds
            Fail-Json -obj $result -message "Timed out while waiting for process(es) to start"
        }

        $Processes = Get-ProcessMatchesFilter -Owner $owner -ProcessNameExact $process_name_exact -ProcessNamePattern $process_name_pattern -ProcessId $process_id
        Start-Sleep -Seconds $sleep
        $attempts ++
        $ProcessCount = $null
        if ($Processes -is [array]) {
            $ProcessCount = $Processes.count
        } elseif ($null -ne $Processes) {
            $ProcessCount = 1
        } else {
            $ProcessCount = 0
        }
    } While ($ProcessCount -lt $process_min_count)

    if ($Processes -is [array]) {
        $result.matched_processes = $Processes
    } elseif ($null -ne $Processes) {
        $result.matched_processes = ,$Processes
    } else {
        $result.matched_processes = @()
    }
}
elseif ($state -eq "absent") {
    # Wait for a process to stop
    $Processes = Get-ProcessMatchesFilter -Owner $owner -ProcessNameExact $process_name_exact -ProcessNamePattern $process_name_pattern -ProcessId $process_id
    if ($Processes -is [array]) {
        $result.matched_processes = $Processes
        $ProcessCount = $Processes.count
    } elseif ($null -ne $Processes) {
        $result.matched_processes = ,$Processes
        $ProcessCount = 1
    } else {
        $result.matched_processes = @()
        $ProcessCount = 0
    }

    if ($result.matched_processes.count -gt 0 ) {
        try {
            Wait-Process -Id $($Processes | Select-Object -ExpandProperty Id) -Timeout $timeout -ErrorAction Stop
        } catch {
            $result.elapsed = ((Get-Date) - $module_start).TotalSeconds
            Fail-Json -obj $result -message "Timeout while waiting for process(es) to stop"
        }
    }
}

Start-Sleep -Seconds $post_wait_delay

$result.elapsed = ((Get-Date) - $module_start).TotalSeconds

Exit-Json -obj $result
