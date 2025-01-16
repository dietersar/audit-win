# audit-win

This script dumps a lot of (Windows) System information for security analysis.

The following files are required:
- autoruns.exe & autoruns64.exe (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- lgpo.exe (from https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- reg.exe
- wsusscn2.cab file from http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab

The script is executed through run_audit.bat, privileges are automatically detected and requested if needed.
