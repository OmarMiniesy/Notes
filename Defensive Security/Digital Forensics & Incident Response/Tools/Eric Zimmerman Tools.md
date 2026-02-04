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
### MFTEcmd

Tool used to analyze the _MFT_ record.

---
### MFTExplorer

Graphical interface tool used to analyze the metadata inside the _MFT_.
- Contains info about files, directories, filenames, and timestamps.
