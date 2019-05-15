#!powershell

# Copyright: (c) 2019, Micah Hunsberger
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

Set-StrictMode -Version 2

$ErrorActionPreference = "Stop"

$spec = @{
    options = @{
        path = @{ type = 'path'; required = $true }
        compressed = @{ type = 'bool'; default = $true }
        recurse = @{ type = 'bool'; default = $false }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$path = $module.Params.path
$compressed = $module.Params.compressed
$recurse = $module.Params.recurse

$module.Result.rc = 0

if(-not (Test-Path -LiteralPath $path)) {
    $module.FailJson("Path to item, $path, does not exist.")
}

$item = Get-Item -LiteralPath $path
if (-not $item.PSIsContainer -or $item.PSDrive.Provider.Name -ne 'FileSystem') {
    $module.FailJson("Path, $path, is not a folder on the filesystem.")
}

$drive_letter = $item.PSDrive.Name
$drive_info = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "$drive_letter`:\" }
if ($drive_info.DriveFormat -ne 'NTFS') {
    $module.FailJson("Path, $path, is not on an NTFS filesystem. Instead, the drive, $drive_letter, is $($drive_info.DriveFormat) format.")
}

function Get-ReturnCodeMessage {
    param(
        [int]$code
    )
    switch ($code) {
        0 { return "The request was successful." }
        2 { return "Access was denied." }
        8 { return "An unspecified failure occurred." }
        9 { return "The name specified was not valid." }
        10 { return "The object specified already exists." }
        11 { return "The file system is not NTFS." }
        12 { return "The platform is not Windows." }
        13 { return "The drive is not the same." }
        14 { return "The directory is not empty." }
        15 { return "There has been a sharing violation." }
        16 { return "The start file specified was not valid." }
        17 { return "A privilege required for the operation is not held." }
        21 { return "A parameter specified is not valid." }
    }
}

if($recurse) {
    # could be a subfolder that is not compressed in this case
    $folders = ([System.IO.Directory]::GetDirectories($item.FullName, '*', [System.IO.SearchOption]::AllDirectories)) + $item.FullName
} else {
    $folders = $item.FullName
}

$needs_changed = $false
foreach ($folder in $folders) {
    $psfolder = Get-Item -LiteralPath $folder
    $is_compressed = ($psfolder.Attributes -band [System.IO.FileAttributes]::Compressed) -eq [System.IO.FileAttributes]::Compressed
    if ($is_compressed -ne $compressed) {
        $needs_changed = $true
        break
    }
}

if($needs_changed) {
    $module.Result.changed = $true
    if($compressed) {
        if(-not $module.CheckMode) {
            $wmi = Invoke-WmiMethod -Path "Win32_Directory.Name='$($item.FullName)'" -Name CompressEx -ArgumentList $recurse
            $module.Result.rc = $wmi.ReturnValue
        }
    } else {
        if(-not $module.CheckMode) {
            $wmi = Invoke-WmiMethod -Path "Win32_Directory.Name='$($item.FullName)'" -Name UnCompressEx -ArgumentList $recurse
            $module.Result.rc = $wmi.ReturnValue
        }
    }
}

$module.Result.msg = Get-ReturnCodeMessage -code $module.Result.rc
if($module.Result.rc -ne 0) {
    $module.FailJson($module.Result.msg)
}

$module.ExitJson()
