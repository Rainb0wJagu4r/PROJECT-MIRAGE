# Register .wraith File Extension and Icon in Windows Registry
param(
    [string]$IconPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $IconPath) {
    $IconPath = Join-Path (Split-Path -Parent $PSScriptRoot) "resources\nobug.ico"
}

$IconPath = [System.IO.Path]::GetFullPath($IconPath)

if (-not (Test-Path $IconPath)) {
    Write-Error "Icon file not found at: $IconPath"
    exit 1
}

Write-Host "Registering Project Mirage .wraith file icon..." -ForegroundColor Cyan
Write-Host "Target Icon: $IconPath" -ForegroundColor Gray

# 1. Associate .wraith extension with ProgID ProjectMirage.wraith
$wraithKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Software\Classes\.wraith")
$wraithKey.SetValue("", "ProjectMirage.wraith", [Microsoft.Win32.RegistryValueKind]::String)
$wraithKey.SetValue("Content Type", "application/x-project-mirage-archive", [Microsoft.Win32.RegistryValueKind]::String)
$wraithKey.SetValue("PerceivedType", "document", [Microsoft.Win32.RegistryValueKind]::String)
$wraithKey.Close()

# 2. Configure ProgID ProjectMirage.wraith
$progIdKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Software\Classes\ProjectMirage.wraith")
$progIdKey.SetValue("", "Project Mirage Encrypted Archive", [Microsoft.Win32.RegistryValueKind]::String)
$progIdKey.SetValue("FriendlyTypeName", "Project Mirage Encrypted Archive (.wraith)", [Microsoft.Win32.RegistryValueKind]::String)
$progIdKey.Close()

# 3. Configure DefaultIcon
$iconKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Software\Classes\ProjectMirage.wraith\DefaultIcon")
$iconFormattedValue = '"' + $IconPath + '",0'
$iconKey.SetValue("", $iconFormattedValue, [Microsoft.Win32.RegistryValueKind]::String)
$iconKey.Close()

# 4. Remove any stale FileExts UserChoice override
$userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wraith\UserChoice"
if (Test-Path $userChoicePath) {
    try {
        Remove-Item -Path $userChoicePath -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

# 5. Broadcast Shell Association Change (SHCNE_ASSOCCHANGED)
$signature = @"
using System;
using System.Runtime.InteropServices;
public class ShellChangeNotifier {
    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
"@

if (-not ([System.Management.Automation.PSTypeName]'ShellChangeNotifier').Type) {
    Add-Type -TypeDefinition $signature
}

[ShellChangeNotifier]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "Success: .wraith icon association registered and Windows Shell refreshed!" -ForegroundColor Green
