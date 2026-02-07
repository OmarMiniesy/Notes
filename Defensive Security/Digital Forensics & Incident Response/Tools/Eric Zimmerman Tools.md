### General Notes

A collection and guides on how to run the different Eric Zimmerman tools I stumbled upon.
- [Link](ericzimmerman.github.io/#!index.md) to all the tools.

> Tools should be run in an elevated command prompt for better usability.

---
### PECmd - Prefetch Parser

Tool used to analyze Windows Prefetch files as part of execution artifacts for [[Windows Forensics]].
- [GitHub Repo](https://github.com/EricZimmerman/PECmd).

The prefetch files are usually found at `C:\Windows\Prefetch`

To run Prefetch Parser on a file and save the results in a CSV, we can use the following command:
```
PECmd.exe -f <path-to-Prefetch-files> --csv <path-to-save-csv>
```

Similarly, for parsing a whole directory, we can use the following command:
```
PECmd.exe -d <path-to-Prefetch-directory> --csv <path-to-save-csv>
```

---
### WxTCmd - Windows 10 Timeline database parser

Tool used to analyze the Windows 10 Timeline SQLite database for recent application execution for [[Windows Forensics]].
- [GitHub Repo](https://github.com/EricZimmerman/WxTCmd).

The Timeline database file is usually found at:
`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<folder>\ActivitiesCache.db`
- Where `<folder>` is `L.username`, or a Microsoft ID, or an Azure Active Directory ID. 

Using the tool:
```
WxTCmd.exe -f <path-to-timeline-file> --csv <path-to-save-csv>
```

---
### JLECmd - Jump List Parser

Tool used to analyze the windows jump list for applications to view recent application execution and the times of execution.
- [GitHub Repo](https://github.com/EricZimmerman/JLEcmd).

The jump list directory is usually present at: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`.

Using the tool:
```
JLECmd.exe -d <path-to-Jumplist-file> --csv <path-to-save-csv>
```

---
### MFTECmd - Master File Table Explorer Command

Used to analyze [[File System#NTFS|NTFS]] metadata artifacts like:
- `$MFT` - [[File System#MFT - Master File Table|Master File Table]]. It extracts and decodes the fields inside the MFT record entries. Check out [[File System#File Record|File Record]] in MFT.
- `$J` - [[File System#Update Sequence Number|USN]] Journal
- `$Boot`, `$LogFile`, `$Secure`, and more.
- [GitHub Repo](https://github.com/EricZimmerman/MFTECmd).

The output of this command can be ingested into the *timeline explorer* tool to view the contents and perform [[DFIR]].  

To analyze the MFT:
```PowerShell
.\MFTECmd.exe -f 'C:\$MFT' --csv <output-dir> --csvf <output-file.csv>
```

To analyze the MFT record of a certain MFT entry:
```powershell
.\MFTECmd.exe -f 'C\$MFT' --de 0x16169
```
- the entry can be specified in either hex or decimal.
- the entry number can be obtained first by first fully parsing the entire MFT table and then locating the needed entry. This can be done by removing the `--de` flag.

To analyze the USN journal, we need to extract the `$J` and `$Max` data streams using [[KAPE]] by specifying the `$Extend\$UsnJrnl` target. Other techniques exist.
- Now, we can use the following command:

``` PowerShell
.\MFTECmd.exe -f 'C:\$Extend\$J' --csv <output-dir> --csvf <output-file.csv>
```

---
### MFTExplorer

Graphical interface tool used to analyze the metadata inside the _MFT_.
- Contains info about files, directories, filenames, and timestamps.

---
