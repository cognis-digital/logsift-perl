# Windows installer for logsift.
# Copies logsift + lib to $env:LOCALAPPDATA\logsift and drops a logsift.cmd launcher.
# Usage:  powershell -ExecutionPolicy Bypass -File install.ps1 [-Prefix <dir>]
param(
    [string]$Prefix = "$env:LOCALAPPDATA\logsift"
)
$ErrorActionPreference = "Stop"
$Src = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
    Write-Error "perl not found in PATH. Install Strawberry Perl or Git-for-Windows Perl."
}

Write-Host "installing logsift -> $Prefix"
New-Item -ItemType Directory -Force -Path "$Prefix\lib\Logsift" | Out-Null
Copy-Item "$Src\logsift.pl" "$Prefix\logsift.pl" -Force
Copy-Item "$Src\lib\Logsift\Parser.pm"    "$Prefix\lib\Logsift\Parser.pm" -Force
Copy-Item "$Src\lib\Logsift\Detectors.pm" "$Prefix\lib\Logsift\Detectors.pm" -Force
Copy-Item "$Src\lib\Logsift\Output.pm"    "$Prefix\lib\Logsift\Output.pm" -Force

$launcher = "$Prefix\logsift.cmd"
"@echo off`r`nperl `"$Prefix\logsift.pl`" %*" | Out-File -FilePath $launcher -Encoding ascii -Force

Write-Host "done."
Write-Host "Add '$Prefix' to your PATH, then run:  logsift --help"
