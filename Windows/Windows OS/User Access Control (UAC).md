### General Notes

This is a window security feature that is used to protect the operating system from unauthorized changes.
- Whenever a change to the system that requires administrator permission is to be taken, the user prompted to accept/deny this action by entering the administrator password.

UAC allows standard users to be logged in and perform normal activities using a low permission account.
- However, once an action that requires elevated privileges is to take place, the user is prompted to accept/deny it by giving it permission.

> To view the users and groups, navigate to **Local user and group management** by typing `lusrmgr.msc` after pressing `WIN + R`.

---
### UAC Settings

The settings for the UAC can be changed through the [[System Configuration]] panel, which can be opened by typing `msconfig` in the windows search.
- Opening the *tools* tab, we see *Change UAC Settings* as an option.

> Changing UAC settings can also be done through the command prompt by entering the command `UserAccountControlSettings.exe`.

---
