### General Notes

This utility is used for advanced troubleshooting, and it has several tabs that show options related to booting, services, startup, and important tools for configuring the operating system.

> It is accessible by typing `msconfig` in windows search.

**General Tab**: This tab shows which devices and services that Windows loads on startup.
**Boot Tab**: This tab shows several boot options for the operating system.
**Services Tab**: Shows all the configured services for the system.
- Services are applications that run in the background.
**Tools Tab**: Shows several tools that can be run to add extra configurations.
- Each tool has a name, description, and the command that will be run if it is selected.

---
#### Change [[User Access Control (UAC)]] Settings

Controls the UAC settings on the computer.
- Can be run by typing the command `UserAccountControlSettings.exe` in the command prompt.

#### Computer Management

This tool contains a collection of administrative tools to manage a windows computer.
- Can be run by typing the command `compmgmt` in the windows search bar.

It has 3 primary sections: 
1. **System Tools**.
2. **Storage**.
3. **Services and Applications**.

###### 1. System Tools

This section has several tools, these are:
- **Task Scheduler**: Similar to cron jobs in Linux, which are tasks that are run at specified times.
- **[[Event Viewer]]**: View events (actions that can be logged) that have occurred on the computer. Used to investigate actions and diagnose problems.
- **Shared Folders**: Shows a list of windows shares and folders that can be accessed by other users. Under the **sessions** tab, a list of users that are connected will be shown. And in **open files**, the current files that are opened.
- **Performance** opens the performance monitor utility (`perfmon`).
- **Device Manager** is used to configure the hardware attached to the computer.

###### 2. Storage

This section has the **Disk Management** tool, which can be used to view the current storage configuration, as well as modify it.

###### 3. Services and Applications

This sections has 2 tools:
- **Services**: This shows the services on the computer and allows for more granular control over the service.
- **WMI**: This is a service that allows scripting languages to manage windows computer, like PowerShell.

### System Information

This tool shows information about the computer and displays a comprehensive view of hardware, system components, and software environment.
- Can be run by typing `msinfo32.exe` in the command prompt.

> Software information includes network information and environment variables.

### Registry Editor

The **Windows Registry** is a central database that stores information about users, applications, and the hardware of a computer.
- To view/edit the registry, the command `regedit.exe` can be typed in the command prompt.

---
