# Backup root folder - Each immediate subfolder will have an ACL backup file created
$BackupSource = "D:\Public"
# Empty folder for backups/reports/logs
$BackupDestination = "H:\ACLBackup"
# Days to keep ACL backups & reports
$Limit = 7
# Create CSV report of subfolder ACLs if True
$SaveReport = $True
# Adds all subfolders to report instead of only immediate ones
$Recurse = $False
# When using $Recurse only adds nested subfolders with explicit permissions
$ExplicitOnly = $True
# Filter access masks from report
$FilterMasks = $False
# Log script info/errors
$ScriptLogOn = $True
# Log ICACLS backup output
$BackupLogOn = $True
# Clear script log at size (MB)
$ScriptLogMax = 10
# Clear backup log at size (MB)
$BackupLogMax = 500
# Exit with message
Function Exit-WithError {
    Param([string]$ErrorMessage)
    Write-Host
    Write-Error -Message "$ErrorMessage"
    Write-Host
    Read-Host "Press enter to exit"
    Exit
}
# Calculated properties for ACLs
Function Format-Acl {
    Param($CurrentAcl,$Directory)
    $CurrentAcl | Select-Object `
        @{Name='Path'; Expression={$Directory}},
        @{Name='Identity'; Expression={$_.IdentityReference}},
        @{Name='Type'; Expression={$_.AccessControlType}},
        @{Name='Inherited'; Expression={$_.IsInherited}},
        @{Name='AccessRights'; Expression={$_.FileSystemRights}}, InheritanceFlags, PropagationFlags
}
# Append logs
Function Add-ToLog {
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Message,
        [Parameter(Mandatory = $True)]
        [string]$LogFile,
        [Parameter(Mandatory = $False)]
        [switch]$WriteHost = $False,
        [Parameter(Mandatory = $False)]
        [switch]$NoTime = $False
    )
    If ($NoTime) {Add-Content -Value "$Message" -Path "$LogFile"}
    Else {
        $MessageTime = Get-Date -UFormat "[%d-%m-%y %H:%M:%S]"
        Add-Content -Value "$MessageTime $Message" -Path "$LogFile"
    }
    If ($WriteHost) {Write-Host "$Message"}
}
# Check paths
If (!(Test-Path "$BackupSource" -PathType Container)) {Exit-WithError -ErrorMessage "The specified backup source [$BackupSource] is not a valid directory.`r`nCorrect the script before attempting any backups or restores."}
If (!(Test-Path "$BackupDestination" -PathType Container)) {Exit-WithError -ErrorMessage "The specified backup destination [$BackupDestination] is not a valid directory.`r`nCorrect the script before attempting any backups or restores."}
Else {
    # Create logs & directories
    If ($ScriptLogOn) {
        $ScriptLog = Join-Path -Path "$BackupDestination" -ChildPath "ScriptLog.txt"
        If (!(Test-Path "$ScriptLog" -PathType Leaf)) {
            $Null = New-Item -Path "$BackupDestination" -Name "ScriptLog.txt" -ItemType File
            If ($?) {Add-ToLog -Message "Created new script log file at [$ScriptLog]" -LogFile "$ScriptLog"}
        }
        Elseif ((Get-Item "$ScriptLog").Length/1000000 -gt $ScriptLogMax) {Clear-Content "$ScriptLog"}
    }
    If ($BackupLogOn) {
        $BackupLog = Join-Path -Path "$BackupDestination" -ChildPath "BackupLog.txt"
        If (!(Test-Path "$BackupLog" -PathType Leaf)) {
            $Null = New-Item -Path "$BackupDestination" -Name "BackupLog.txt" -ItemType File
            If ($? -and $ScriptLogOn) {Add-ToLog -Message "Created new backup log file at [$BackupLog]" -LogFile "$ScriptLog"}
            Elseif ($ScriptLogOn) {Add-ToLog -Message "Failed to create backup log at [$BackupLog]" -LogFile "$ScriptLog"}
        }
        Elseif ((Get-Item "$BackupLog").Length/1000000 -gt $BackupLogMax) {Clear-Content "$BackupLog"}
    }
    If ($SaveReport) {
        $ReportFolder = Join-Path -Path "$BackupDestination" -ChildPath "Reports"
        If (!(Test-Path "$ReportFolder" -PathType Container)) {
            $Null = New-Item -Path "$BackupDestination" -Name "Reports" -ItemType Directory
            If ($? -and $ScriptLogOn) {Add-ToLog -Message "Created directory for reports at [$ReportFolder]" -LogFile "$ScriptLog"}
            Elseif ($ScriptLogOn) {Add-ToLog -Message "Failed to create report dir at [$ReportFolder]" -LogFile "$ScriptLog"}
        }
    }
    $BackupFolder = Join-Path -Path "$BackupDestination" -ChildPath "Backups"
    If (!(Test-Path "$BackupFolder" -PathType Container)) {
        $Null = New-Item -Path "$BackupDestination" -Name "Backups" -ItemType Directory
        If ($? -and $ScriptLogOn) {Add-ToLog -Message "Created root directory for backups at [$BackupFolder]" -LogFile "$ScriptLog"}
        Elseif ($ScriptLogOn) {Add-ToLog -Message "Failed to create root dir at [$BackupFolder]" -LogFile "$ScriptLog"}
    }
    If ($BackupSource -match "\\$") {$BackupSource = $BackupSource -replace "\\+$"}
}
# You must select 'Run whether user is logged on or not' in Task Scheduler for this If/Else statement to work!
If ([Environment]::UserInteractive) {
    # Check/request elevation
    $MyWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $MyWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($MyWindowsID)
    $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    If ($MyWindowsPrincipal.IsInRole($AdminRole)) {
        $Host.UI.RawUI.WindowTitle = $MyInvocation.MyCommand.Definition + "(Elevated)"
        $Host.UI.RawUI.BackgroundColor = "Black"
        Clear-Host
    }
    Else {
        $NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
        $NewProcess.Arguments = $MyInvocation.MyCommand.Definition;
        $NewProcess.Verb = "runas";
        [System.Diagnostics.Process]::Start($NewProcess);
        Trap {continue}
        Exit
    }
    If ($ScriptLogOn) {
        Add-ToLog -Message "--------------------------------------------" -LogFile "$ScriptLog"
        Add-ToLog -Message "Script started in interactive (restore) mode" -LogFile "$ScriptLog"
        Add-ToLog -Message "--------------------------------------------" -LogFile "$ScriptLog"
    }
    $RestoreFolders = Get-ChildItem -Path "$BackupFolder" | Where {$_.PSIsContainer}
    Write-Host "This is a 2-in-1 script for backups and restores of NTFS permissions"
    Write-Host "using the built-in icacls.exe utility. You can schedule backups"
    Write-Host "from task scheduler and run it interactively to perform restores."
    Write-Host
    Write-Host "Backup Source: $BackupSource"
    Write-Host "Backup Destination: $BackupFolder"
    Write-Host "Backup Retention: $Limit Days [$((Get-Date).AddDays(-$Limit).ToString().Substring(0,10))]"
    Write-Host "Number of Backups: $(($RestoreFolders | Measure).Count)"
    Write-Host
    $RestorePrompt = ""
    While ("YES","Y","NO","N" -notcontains $RestorePrompt) {$RestorePrompt = (Read-Host "Would you like to attempt a restore?(Y/N)").ToUpper()}
    If (("YES","Y" -contains $RestorePrompt) -and (($RestoreFolders | Measure).Count -gt 0)) {
        $RetryPrompt = ""
        While ("NO","N" -notcontains $RetryPrompt) {
            If ($ScriptLogOn) {Add-ToLog -Message "User selected attempt restore" -LogFile "$ScriptLog"}
            Write-Host
            Write-Host "The following dates/times are available:"
            Write-Host
            # List backups
            For ($FolderCount = 0; $FolderCount -lt $RestoreFolders.Count; $FolderCount++) {
                $DisplayNumber = $FolderCount+1
                Write-Host "$DisplayNumber) $($RestoreFolders[$FolderCount].Name)"
            }
            Write-Host
            $NumberRange = 1..($RestoreFolders.Count)
            $NumberPrompt = ""
            # Choose backup
            While ($NumberRange -notcontains $NumberPrompt) {$NumberPrompt = Read-Host "Enter the number for your choice"}
            $SelectedFolder = $RestoreFolders[($NumberPrompt-1)]
            If ($ScriptLogOn) {Add-ToLog -Message "User selected backup [$($SelectedFolder.Name)]" -LogFile "$ScriptLog"}
            $RestoreFiles = Get-ChildItem -Path "$($SelectedFolder.FullName)" | Where {!$_.PSIsContainer}
            If (($RestoreFiles | Measure).Count -gt 0) {
                Write-Host
                Write-Host "The following ACL backups are available for [$($SelectedFolder.Name)]:"
                Write-Host
                # List ACLs
                For ($FileCount = 0; $FileCount -lt $RestoreFiles.Count; $FileCount++) {
                    $DisplayNumber = $FileCount+1
                    Write-Host "$DisplayNumber) $($RestoreFiles[$FileCount].Name)"
                }
                Write-Host
                $NumberRange = 1..($RestoreFiles.Count)
                $NumberPrompt = ""
                # Choose ACL
                While ($NumberRange -notcontains $NumberPrompt) {$NumberPrompt = Read-Host "Enter the number for your choice"}
                $SelectedACL = $RestoreFiles[($NumberPrompt-1)]
                If ($ScriptLogOn) {Add-ToLog -Message "User selected ACL file [$($SelectedACL.Name)]" -LogFile "$ScriptLog"}
                Write-Host
                $ConfirmPrompt = ""
                Write-Host "You are about to attempt the following restore:"
                Write-Host
                Write-Host "Selected ACL file: $($SelectedACL.Name)"
                Write-Host "Selected backup: $($SelectedFolder.Name)"
                Write-Host "Restore destination: $BackupSource"
                Write-Host
                While ("YES","Y","NO","N" -notcontains $ConfirmPrompt) {$ConfirmPrompt = (Read-Host "Are you sure you wish to continue?(Y/N)").ToUpper()}
                If ("YES","Y" -contains $ConfirmPrompt) {
                    Write-Host
                    If ($ScriptLogOn) {
                        Add-ToLog -Message "Attempting to restore permissions for [$($SelectedACL.Name)] from [$($SelectedFolder.Name)]" -LogFile "$ScriptLog" -WriteHost
                    }
                    Else {Write-Host "Attempting to restore permissions for [$($SelectedACL.Name)] from [$($SelectedFolder.Name)]"}
                    Write-Host
                    $RestoreStart = Get-Date
                    $RestoreParams = @{
                        FilePath = "icacls.exe"
                        ArgumentList = "`"$BackupSource`" /restore `"$($SelectedACL.FullName)`""
                        Wait = $True
                        PassThru = $True
                        NoNewWindow = $True
                    }
                    $RestoreProc = Start-Process @RestoreParams
                    $RestoreTime = (Get-Date)-$RestoreStart
                    If ($ScriptLogOn) {
                        $UnknownExitCode = $False
                        Switch ($RestoreProc.ExitCode) {
                            0 {
                                $RestoreMessage = "Successfully restored permissions for [$($SelectedACL.Name)]"
                                Break
                            }
                            2 {
                                $RestoreMessage = "One or more files were not found during the restore"
                                Break
                            }
                            123 {
                                $RestoreMessage = "File/Directory/Volume name or syntax is incorrect"
                                Break
                            }
                            160 {
                                $RestoreMessage = "Bad arguments were passed to command"
                                Break
                            }
                            1300 {
                                $RestoreMessage = "Not all privileges assigned to caller, please ensure script is running as admin"
                                Break
                            }
                            Default {
                                $UnknownExitCode = $True
                                $RestoreMessage = "An unexpected error occurred, the exit code was $($RestoreProc.ExitCode)"
                                Break
                            }
                        }
                        Add-ToLog -Message "$RestoreMessage" -LogFile "$ScriptLog"
                        If ($UnknownExitCode) {Add-ToLog -Message "For information on the exit code please visit 'https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx'" -LogFile "$ScriptLog"}
                        Write-Host
                        Add-ToLog -Message "Restore attempt for [$($SelectedACL.Name)] took $($RestoreTime.TotalSeconds.ToString("0.00")) seconds" -LogFile "$ScriptLog" -WriteHost
                    }
                    Else {
                        Write-Host
                        Write-Host "Restore attempt for [$($SelectedACL.Name)] took $($RestoreTime.TotalSeconds.ToString("0.00")) seconds"
                    }
                }
                Elseif ($ScriptLogOn) {Add-ToLog -Message "User cancelled restore attempt at confirmation prompt" -LogFile "$ScriptLog"}
                Write-Host
            }
            # No backups in folder
            Else {
                Write-Host
                If ($ScriptLogOn) {Add-ToLog -Message "No ACL backup files were found in folder [$($SelectedFolder.Name)]" -LogFile "$ScriptLog" -WriteHost}
                Else {Write-Host "No ACL backup files were found in folder [$($SelectedFolder.Name)]"}
                Write-Host
            }
            $RetryPrompt = ""
            While ("YES","Y","NO","N" -notcontains $RetryPrompt) {$RetryPrompt = (Read-Host "Would you like to try another restore?(Y/N)").ToUpper()}
            If ("NO","N" -contains $RetryPrompt -and $ScriptLogOn) {Add-ToLog -Message "Script exited at retry prompt" -LogFile "$ScriptLog"}
        }
    }
    # No backup folders
    Elseif (("YES","Y" -contains $RestorePrompt) -and (($RestoreFolders | Measure).Count -eq 0)) {
        Write-Host
        Write-Warning "No backups to restore!"
        Write-Host
        Read-Host "Press enter to exit"
        If ($ScriptLogOn) {Add-ToLog -Message "Script exited, user attempted restore but no backups exist" -LogFile "$ScriptLog"}
    }
    Elseif ($ScriptLogOn) {Add-ToLog -Message "Script exited, no restore attempt made" -LogFile "$ScriptLog"}
}
Else {
    # Non-interactive session/scheduled task (backup)
    $BackupStart = Get-Date
    If ($ScriptLogOn) {
        Add-ToLog -Message "-----------------------------------------------" -LogFile "$ScriptLog"
        Add-ToLog -Message "Script started in non-interactive (backup) mode" -LogFile "$ScriptLog"
        Add-ToLog -Message "-----------------------------------------------" -LogFile "$ScriptLog"
    }
    Function Get-ProcessOutput {
        Param(
            [Parameter(Mandatory=$True)]
            [String]$Command,
            [String]$ArgList,
            [Switch]$NoWindow = $False,
            [Switch]$UseShell = $False,
            [Switch]$WaitForOutput = $False
        )
        $ProcInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcInfo.CreateNoWindow = $NoWindow
        $ProcInfo.FileName = $Command
        $ProcInfo.RedirectStandardError = $True
        $ProcInfo.RedirectStandardOutput = $True
        $ProcInfo.UseShellExecute = $UseShell
        $ProcInfo.Arguments = $ArgList
        $ProcObject = New-Object System.Diagnostics.Process
        $ProcObject.StartInfo = $ProcInfo
        $Null = $ProcObject.Start()
        If ($WaitForOutput) {
            $Output = $ProcObject.StandardOutput.ReadToEnd()
            $ProcObject.WaitForExit()
            $Output
        }
        Else {
            Do {
                $ProcObject.StandardOutput.ReadLine()
            } Until ($ProcObject.HasExited)
            $ProcObject.StandardOutput.ReadToEnd()
            $ProcObject.WaitForExit()
        }
    }
    $SourceFolders = Get-ChildItem -Path "$BackupSource" | Where {$_.PSIsContainer}
    If ($ScriptLogOn) {Add-ToLog -Message "Found $(($SourceFolders | Measure).Count) directories in [$BackupSource] to backup" -LogFile "$ScriptLog"}
    $CurrentDate = Get-Date -UFormat %d-%m-%Y_%H-%M
    $BackupName = $CurrentDate
    $FolderIncrement = 0
    While (Test-Path -Path "$BackupFolder\$BackupName" -PathType Container) {
        $FolderIncrement++
        $BackupName = "$CurrentDate`_$FolderIncrement"
    }
    If ($SaveReport) {$ExportArray = @()}
    $NoFolders = $False
    If (($SourceFolders | Measure).Count -gt 0) { # << v2 compatibility
        $Null = New-Item -Path "$BackupFolder" -Name "$BackupName" -ItemType Directory
        If ($? -and $ScriptLogOn) {Add-ToLog -Message "Created backup directory at [$BackupFolder\$BackupName]" -LogFile "$ScriptLog"}
        If ($BackupLogOn) {
            Add-ToLog -Message "#############################################" -LogFile "$BackupLog" -NoTime
            Add-ToLog -Message "### Backup Started At $BackupStart ###" -LogFile "$BackupLog" -NoTime
            Add-ToLog -Message "#############################################`r`n" -LogFile "$BackupLog" -NoTime
        }
        If ($SaveReport) {
            If ($FilterMasks) {$SourceAcl = (Get-Acl -Path "$BackupSource").Access | Where {$_.FileSystemRights -notmatch "^[\d\-]"}}
            Else {$SourceAcl = (Get-Acl -Path "$BackupSource").Access}
            $ExportArray += Format-Acl -CurrentAcl $SourceAcl -Directory "$BackupSource"
        }
        Foreach ($Folder in $SourceFolders) {
            If ($SaveReport) {
                If ($ScriptLogOn) {Add-ToLog -Message "Adding [$($Folder.Name)] to CSV report" -LogFile "$ScriptLog"}
                If ($FilterMasks) {$VarAcl = $Folder.GetAccessControl().Access | Where {$_.FileSystemRights -notmatch "^[\d\-]"}}
                Else {$VarAcl = $Folder.GetAccessControl().Access}
                $ExportArray += Format-Acl -CurrentAcl $VarAcl -Directory "$($Folder.FullName)"
                If ($Recurse) {
                    $SubDirEx = $False
                    If ($ExplicitOnly) {
                        If ($ScriptLogOn) {Add-ToLog -Message "Getting subfolders of [$($Folder.Name)] with explicit permissions" -LogFile "$ScriptLog"}
                        Try {$AllSubDirs = Get-ChildItem -Path "$($Folder.FullName)" -Recurse | Where {$_.PSIsContainer -and $_.GetAccessControl().Access.IsInherited -contains $False}}
                        Catch {$SubDirEx = $True}
                    }
                    Else {
                        If ($ScriptLogOn) {Add-ToLog -Message "Getting all subfolders of [$($Folder.Name)]" -LogFile "$ScriptLog"}
                        Try {$AllSubDirs = Get-ChildItem -Path "$($Folder.FullName)" -Recurse | Where {$_.PSIsContainer}}
                        Catch {$SubDirEx = $True}
                    }
                    If (($AllSubDirs | Measure).Count -gt 0) { # << v2 compatibility
                        If ($ExplicitOnly -and $ScriptLogOn) {Add-ToLog -Message "Found $(($AllSubDirs | Measure).Count) subfolder(s) with explicit permissions in [$($Folder.Name)]" -LogFile "$ScriptLog"}
                        Elseif ($ScriptLogOn) {Add-ToLog -Message "Found $(($AllSubDirs | Measure).Count) total subfolder(s) in [$($Folder.Name)]" -LogFile "$ScriptLog"}
                        If ($SubDirEx -and $ScriptLogOn) {
                            Add-ToLog -Message "WARNING: Subfolders were found but Get-ChildItem raised one or more exceptions" -LogFile "$ScriptLog"
                            Add-ToLog -Message "Please ensure the user executing the script can access all subfolders of [$($Folder.Name)]" -LogFile "$ScriptLog"
                        }
                        Foreach ($SubDir in $AllSubDirs) {
                            If ($FilterMasks) {$VarSubAcl = $SubDir.GetAccessControl().Access | Where {$_.FileSystemRights -notmatch "^[\d\-]"}}
                            Else {$VarSubAcl = $SubDir.GetAccessControl().Access}
                            $ExportArray += Format-Acl -CurrentAcl $VarSubAcl -Directory "$($SubDir.FullName)"
                        }
                    }
                    Elseif (($AllSubDirs | Measure).Count -eq 0 -and !$SubDirEx -and $ScriptLogOn) {
                        If ($ExplicitOnly) {Add-ToLog -Message "No subfolders with explicit permissions were found in [$($Folder.Name)]" -LogFile "$ScriptLog"}
                        Else {Add-ToLog -Message "No subfolders were found in [$($Folder.Name)]" -LogFile "$ScriptLog"}
                    }
                    Elseif (($AllSubDirs | Measure).Count -eq 0 -and $SubDirEx -and $ScriptLogOn) {
                        Add-ToLog -Message "WARNING: Get-ChildItem raised one or more exceptions when attempting to access [$($Folder.Name)]" -LogFile "$ScriptLog"
                        Add-ToLog -Message "Please ensure the user executing the script can access [$($Folder.Name)]" -LogFile "$ScriptLog"
                    }
                }
            }
            If ($ScriptLogOn) {
                $ACLStart = Get-Date
                Add-ToLog -Message "Performing ACL backup of [$($Folder.Name)]" -LogFile "$ScriptLog"
            }
            $BackupParams = @{
                Command = "icacls.exe"
                ArgList = "`"$($Folder.FullName)`" /save `"$BackupFolder\$BackupName\$($Folder.Name)`" /T /C"
                WaitForOutput = $True
                NoWindow = $True
            }
            $BackupOutput = Get-ProcessOutput @BackupParams
            If ($ScriptLogOn) {
                $ACLBackupTime = (Get-Date)-$ACLStart
                Add-ToLog -Message "Backup/attempt of [$($Folder.Name)] took $($ACLBackupTime.TotalSeconds.ToString("0.00")) seconds" -LogFile "$ScriptLog"
            }
            If ($BackupLogOn) {
                $HyphenLine = "-"*($Folder.Name.Length + 41)
                Add-ToLog -Message "$HyphenLine" -LogFile "$BackupLog" -NoTime
                Add-ToLog -Message "ICACLS output for [$($Folder.Name)]:`r`n$BackupOutput" -LogFile "$BackupLog"
            }
        }
    }
    Else {
        $NoFolders = $True
        If ($ScriptLogOn) {Add-ToLog -Message "No directories to backup!" -LogFile "$ScriptLog"}
    }
    $RetentionLimit = (Get-Date).AddDays(-$Limit)
    If ($SaveReport) {
        If (!$NoFolders) {
            $ExportArray | Export-Csv -Path "$ReportFolder\PermissionsSummary_$BackupName.csv" -Force -NoTypeInformation
            If ($? -and $ScriptLogOn) {Add-ToLog -Message "Exported CSV report to [$ReportFolder\PermissionsSummary_$BackupName.csv]" -LogFile "$ScriptLog"}
        }
        $OldReports = Get-ChildItem -Path "$ReportFolder" | Where {!$_.PSIsContainer -and $_.CreationTime -lt $RetentionLimit}
        If (($OldReports | Measure).Count -gt 0) {
            If ($ScriptLogOn) {Add-ToLog -Message "Deleting $($OldReports.Count) old report(s) from [$ReportFolder]" -LogFile "$ScriptLog"}
            $OldReports | Remove-Item -Force
        }
        Elseif ($ScriptLogOn) {Add-ToLog -Message "No reports found older than $RetentionLimit" -LogFile "$ScriptLog"}
    }
    $OldBackups = Get-ChildItem -Path "$BackupFolder" | Where {$_.PSIsContainer -and $_.CreationTime -lt $RetentionLimit}
    If (($OldBackups | Measure).Count -gt 0) {
        If ($ScriptLogOn) {Add-ToLog -Message "Deleting $($OldBackups.Count) old backup(s) from [$BackupFolder]" -LogFile "$ScriptLog"}
        $OldBackups | Remove-Item -Force -Recurse
    }
    Elseif ($ScriptLogOn) {Add-ToLog -Message "No backups found older than $RetentionLimit" -LogFile "$ScriptLog"}
    If ($ScriptLogOn) {
        $BackupRuntime = (Get-Date)-$BackupStart
        Add-ToLog -Message "Total runtime (D:H:M:S) - $($BackupRuntime.Days):$($BackupRuntime.Hours):$($BackupRuntime.Minutes):$($BackupRuntime.Seconds)" -LogFile "$ScriptLog"
        Add-ToLog -Message "ACL backup complete" -LogFile "$ScriptLog"
        If ($Error.Count -gt 0) {
            $CurrentErrors = $Error | Get-Unique
            Add-ToLog -Message "***Summary of script errors***" -LogFile "$ScriptLog"
            Foreach ($Item in $CurrentErrors) {
                ($Item | Out-String) -split "\r\n" | ForEach-Object {
                    If ($_ -notmatch "^\s*$") {Add-ToLog -Message "$_" -LogFile "$ScriptLog"}         
                }
            }
        }
    }
}