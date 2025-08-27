### General Notes

GPP, or [[Group Policy Object#Group Policy Preferences|Group Policy Preferences]], are stored in [[XML]] policy files that are encrypted using the [same AES private key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be) across all [[Active Directory]] environments.
- The policy files are stored in [[Domain Controller#SYSVOL|SYSVOL]], and can be decrypted by any authenticated user using this key.
- Sometimes, these policy files include passwords that can be decrypted using the shared key.

> XMLs containing encrypted passwords store it in the `cpassword` property.

---
### Attack Path

To detect and decrypt if any passwords exist in the policy files, the `Get-GPPPassword` function from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master) can be utilized.
- This parses all XML files in the *Policies* folder in `SYSVOL` and decrypts passwords in the `cpassword` property.

```powershell
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

To execute this attack, we first need to:
1. Open PowerShell as administrator user.
2. Set *Execution Policy* to *Unrestricted*:
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

---
### Prevention & Detection

A patch was released by Microsoft to prevent passwords from being stored in policy files.
- The patch does not clear existing stored credentials, it only prevents the caching of new ones.

> However, there are still environments that have passwords in the policy files regardless of the patch.

To detect this attack done by the `GPPPassword` tool, we can check for file access events using [[Windows Events Log]] event with ID `4663`.
- We can then check for failed, successful, or TGT request events (`4624`, `4624`, `4768` respectively) and mapping on the [[IP]] address used to check if it is normal behavior.

Honeypots can also be used:
- A semi-privileged user with a *wrong password*.
- Having an old password with no recent changes.
- Should have recent logon attempts.
- Then, we setup an alert on failed login attempts for this user on the Event IDs `4625, 4771, 4776`.

---
