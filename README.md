Scripts that change registry entries pointing to a new empty profile after AD migration.

**The Norwegian scripts are original versions and not updated to handle SCCM clients, check versioning.**

Current production scripts:

- Detect-ProfileRemediation_EN.ps1
  - Intune detection script for use in a proactive remediation package(English).
  - Verifies that ProfileRemediation infrastructure is installed: version file, required files, and scheduled tasks.
  - Exits 0 when the deployment is complete; exits 1 when remediation or reinstall is needed.

- Detect-ProfileRemediation_NO.ps1
  - Norwegian language version of the detection script.
  - Performs the same infrastructure checks as the EN version.

- Install-ProfileRemediation_EN.ps1
  - Must be run as system and installs the solution so it runs *the next time the user logs on* after installation.
  - Installation/deployment script (English).
  - Installs ProfileRemediation scripts and scheduled tasks on computers.
  - Writes overlay and engine scripts to C:\ProgramData\ProfileRemediation and creates the logon tasks.

- Install-ProfileRemediation_NO.ps1
  - Norwegian language version of the installation script.
  - Performs the same deployment steps as the EN version.

- Fix-ProfileACL.ps1
  - Standalone ACL repair script. *Only to be used if the Original version of the Install-Profileremeddiation without ACL fix were used on local clients.*
  - Scans completed remediation markers and updates NTFS ownership and permissions for the original profile folders.
  - Supports an optional -UserName parameter to limit the fix to a single user.

- Invoke-ProfileFix.ps1
  - Standalone on-demand repair script for administrators. *Will swicth user working in the ned .AD profil back to the original profile without .AD*
  - **Can be run on any client by a user or engineer with local admin rights.**
  - Detects duplicate .AD profiles, backs up ProfileList, remaps the registry, removes the empty .AD profile, updates ACLs, and notifies the user.

- Restore-ProfileRemediationSilent_EN.ps1
  - Silent SYSTEM rollback script (English).
  - Restores remediated profiles from registry backups and recreates the .AD profile state when rollback is required.
