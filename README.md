This script allows you to perform rolling scheduled backups and restores of NTFS permissions/ACLs using the icacls.exe utility. 
It has been designed as multi-purpose, meaning it can be run from task scheduler to perform a backup and run interactively
in order to perform a restore.

When creating the backup job in task scheduler the you must ensure that the radio button 'Run whether user is logged on or not' 
is selected, otherwise the script will interpret it as an interactive session (restore). It is advisable to run it as an administrator with highest privileges as well in case of any restrictions when querying the ACLs.

Features:
 - CSV report of folder ACLs with additional switches for recursion (All/Explicit Only)
 - Log files for script & icacls output
 - User-defined limits for backup/report retention and log sizes
 - PS v2 compatible (I believe) - better to use at least v3 if you can
