### General Notes

Important locations for the [[Windows Registry]] while performing [[DFIR]].
- The notation here used is that of the registry key location. To check the hive location on disk, check out [[Windows Registry#Accessing the Registry Hives|Registry Hive Locations]].
- Reminder that `HKEY_CURRENT_USER` maps to `NTUSER.DAT` and that `HKEY_CURRENT_USER\Software\CLASSES` maps to `USRCLASS.DAT`.

> [[Eric Zimmerman Tools]] - Registry Explorer or [[RegRipper]] to try and extract this information.

---
### System Information & Accounts

**OS Version**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
**Computer Name**: `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
**Time Zone**: `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
**Network Interfaces**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
**Past Networks**: `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Unmanaged` and `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Managed`
**User Account Information**: `SAM\Domains\Account\Users`

---
### Files & Folders

**Recently Opened Files**: 
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- To look for specific file type, such as `pdf`: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`

**Recently Opened Office Files**:
- `HKEY_CURRENT_USER\Software\Microsoft\<version>`, for example, `HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word`
- For Office 365, `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\UserMRU\LiveID_####\FileMRU`

**Shellbags**: - [[Windows Forensics#File System NTFS NTFS|Shellbags]], Information about the windows shell, or the layout in which folders are opened. Has information 
- `HKEY_CURRENT_USER\Software\CLASSES\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `HKEY_CURRENT_USER\Software\CLASSES\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags`

**Open/Save file**: When a file is to opened or saved, a dialog box appears asking where to save the file or where to open the file from. Recently used files can be identified if we obtain these locations.
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

**Windows Explorer Search Bar**: Look at the paths typed in the windows explorer address bar or any searches performed.
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

---
### Execution Evidence - [[Windows Forensics#Execution Artifacts|Windows Execution Artifacts]]

**Prefetch**: This is a feature that optimizes the loading of application by preloading certain components. A prefetch file is created for every program that is executed on a Windows system. The naming convention of prefetch files is the original name of the executable followed by a hex value of the path of where it resides. The files end with a `.pf` extension.
- Stored in the `C:\Windows\Prefetch\` directory.
- Can be analyzed using the [[Eric Zimmerman Tools#PECmd - Prefetch Parser|PECmd]] tool by Eric Zimmerman.

**UserAssist**: This contains information about program launches, the time of launch, the focus time, and the number of launch times. *Does not contain programs run using the command line*. It groups the runs by the user GUID: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\count`

**Shimcache (AppCompatCache)**: Ensures application backward compatibility and stores information about the executables, including name, size, and last modified date. The key found in the registry: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

**Amcache**: Similar to Shimcache, and it also stores data related to program execution, including path, installation, deletion, execution times, and a SHA1 hash. Can be analyzed using [[Eric Zimmerman Tools]], the *AmcacheParser* : `C:\Windows\appcompat\Programs\Amcache.hve`. 
- Last executed programs can be found at:`C:\Windows\appcompat\Programs\Amcache.hve\Root\File\{volume guid}`

**BAM/DAM - Background Activity Monitor/Desktop Activity Monitor**: These contain information about last run programs, their full paths, and the execution times. Can be analyzed using [[RegRipper]] or *Registry Explorer* by Eric Zimmerman. 
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`

---
### External Devices

To check if any USB or removable devices were attached, the following registry keys are useful.

**Device Identification**: These keep track of USBs plugged, storing the vendor id, the product id, the version, and the time it was plugged.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB`

**Device Name**: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Portable Devices\Devices`

---
