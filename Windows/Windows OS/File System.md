### NTFS

Windows systems utilize **NTFS**, or New Technology File System, which gave way to new features like:
- Supporting larger files.
- Folder and file compression.
- [[Encryption]] using **EFS**, Encrypted File System.

The permissions for files and folders are:
- Read
- Write
- List folder contents
- Modify (reading, writing, deleting)
- Read and Execute
- Full Control.

> The permissions of  a file or folder can be viewed by right clicking and then going to properties then security tab.

##### Operating System Files

The operating system is usually found at `C:\Windows`.
- Not always the case.
- The location of that folder is stored in the `%windir%` environment variable.

The `C:\Windows\System32` folder is essential, as it holds the files necessary for the Operating System to function, such as the [[Windows Registry]] hives.

##### Data Streams

A data stream is a sequence of bytes that stores the file data.
- Files have at least one data stream, the unnamed one, which has the main file content. Sometimes called `$DATA`

There are also *Alternate Data Streams (ADS)* which are named data streams that can store additional information for the file, such as metadata.
- ADS are not visible through the Windows Explorer, and they are used to store keywords, user information, thumbnails, and small executable files.
- There are utilities that allow for the viewing this metadata in the ADS.
- These have been used by [[Malware]] to hide data

> Using the syntax `<file-name>:<stream-name>` allows reading and writing to the stream called `stream-name` of the file called `<file-name>`.

To list all the alternate data streams for files in a directory:
```powershell
Get-Item * -Stream *
```

To read the content of a specific file stream of a specific file:
```powershell
Get-Content file.exe -Stream Zone.Identifier
```

##### Zone.Identifier

This is an alternate data stream that is used to signify how the file came to be on the host.
- It stores *Mark of the Web (MOTW)* information, to identify whether the file was downloaded from the internet or not.
- This is how windows tells programs that this file might be unsafe because it was downloaded from the internet for example.

```
example.exe:Zone.Identifier:$DATA
```

The content of this data stream contains the links and [[IP]]s of where it was downloaded from, as well as the *ZoneId*, which can be :
- 0 → Local machine
- 1 → Local intranet
- 2 → Trusted sites
- 3 → Internet
- 4 → Restricted zone

> Zone.Identifier data can be viewed in the output of the [[Eric Zimmerman Tools#MFTEcmd - Master File Table Explorer Command|MFTECmd]] CSV file as it is a *resident* record.

##### Journaling

The NTFS file system keeps a log of changes to the metadata of the volume, helping the system recover from crashes.
- This log is stored in the `$LOGFILE` in the root directory of the volume.

##### File Deletion

When a file is deleted, the file system deletes the entries that the store the file location on the disk.
- The location where the file existed is now available for writing again.
- The actual content of the file deleted is still present on the disk, as long as it has not been rewritten.

##### Update Sequence Number

The *Update Sequence Number*, or *USN*, is a journal that logs alterations to files and directories.
- Allows monitoring file creation, renaming, deletion, and data overwriting.
- The file is present in the `$Extend` directory and is called `$UsnJrnl`.
- The actual entries are stores in the `$J` data stream.
- There is another stream called `$Max` that contains the configuration information for the journal itself

```PowerShell
C:\$Extend\$UsnJrnl:$J
C:\$Extend\$UsnJrnl:$Max
```
- Can be analyzed using the [[Eric Zimmerman Tools#MFTEcmd - Master File Table Explorer Command|MFTECmd]] Zimmerman tool.

---
### MFT - Master File Table

The MFT is a file that is used to catalog the files and directories on an NTFS volume, where each file and directory has an entry in it with metadata and other details, including file creation, modification, deletion, and access.
- The MFT also allows for the creation of timelines of events using the [[#MAC(b) Times in NTFS]].
- The MFT also holds data about files and directories even after they are deleted.

> The MFT is stored in `C:\$MFT`. The `$` symbolizes that this file is part of the NTFS itself and is not meant for user modification. Can be visualized using [Active@ Disk Editor](https://www.disk-editor.org/index.html) or by [[Eric Zimmerman Tools]]. 

##### File Record

Entries in the MFT are called *records*, and records have a structured format that contain *attribute records* about the file *The MFT record is 1024 bytes long*. Each file record has the following `$ATTRIBUTE` records:
- **File Record Header**: Metadata about the file record itself:
	- *Signature*: 4 bytes that is either `FILE` if the record is in use or `BAAD` if deallocated.
	- *Offset to Update Sequence Array*: Offset for the *USA* that maintains the integrity of record during updates.
	- *Size of Update Sequence Array*: The size of the USA in words.
	- *Log File Sequence Number*: This number identifies the last update to the file record.
	- *Sequence Number*: Number that identifies the file record. The records are numbered sequentially starting 0.
	- *Hard Link Count*: The number of hard links, or how many directory entries point to the file record.
	- *Offset to First Attribute*: Offset to the first attribute in the record.
- **Standard Information Attribute Header** (`$STANDARD_INFORMATION`, `$10`): Metadata about the file, like timestamps, file attributes, and security identifiers.
- **File Name Attribute Header** (`$FILE_NAME`, `$30`): Information about filename length, namespace, and characters.
- **Data Attribute Header** (`$DATA`, `$80`): Describes the content of the file, which can be *resident* or *non-resident*. For files that are smaller than 512 bytes, the content is stored in side the MFT table and it is called resident. For larger files, the data is referenced from clusters on the disk and it is called non-resident. 
- **Additional Attributes**: Security descriptors, Object IDs, Volume, index, ...

| Type        | Attribute              | Description                                                                      |
| ----------- | ---------------------- | -------------------------------------------------------------------------------- |
| 0x10 (16)   | $STANDARD_INFORMATION  | General information - flags, MAC times, owner, and security id.                  |
| 0x20 (32)   | $ATTRIBUTE_LIST        | Pointers to other attributes and a list of nonresident attributes.               |
| 0x30 (48)   | $FILE_NAME             | File name - (Unicode) and outdated MAC times                                     |
| 0x40 (64)   | $VOLUME_VERSION        | Volume information - NTFS v1.2 only and Windows NT, no longer used               |
| 0x40 (64)   | $OBJECT_ID             | 16B unique identifier - for file or directory (NTFS 3.0+; Windows 2000+)         |
| 0x50 (80)   | $SECURITY_DESCRIPTOR   | File's access control list and security properties                               |
| 0x60 (96)   | $VOLUME_NAME           | Volume name                                                                      |
| 0x70 (112)  | $VOLUME_INFORMATION    | File system version and other information                                        |
| 0x80 (128)  | $DATA                  | File contents                                                                    |
| 0x90 (144)  | $INDEX_ROOT            | Root node of an index tree                                                       |
| 0xA0 (160)  | $INDEX_ALLOCATION      | Nodes of an index tree - with a root in $INDEX_ROOT                              |
| 0xB0 (176)  | $BITMAP                | Bitmap - for the $MFT file and for indexes (directories)                         |
| 0xC0 (192)  | $SYMBOLIC_LINK         | Soft link information - (NTFS v1.2 only and Windows NT)                          |
| 0xC0 (192)  | $REPARSE_POINT         | Data about a reparse point - used for a soft link (NTFS 3.0+; Windows 2000+)     |
| 0xD0 (208)  | $EA_INFORMATION        | Used for backward compatibility with OS/2 applications (HPFS)                    |
| 0xE0 (224)  | $EA                    | Used for backward compatibility with OS/2 applications (HPFS)                    |
| 0x100 (256) | $LOGGED_UTILITY_STREAM | Keys and other information about encrypted attributes (NTFS 3.0+; Windows 2000+) |

---
### MAC(b) Times in NTFS

These are the *timestamps* for files or objects and they showcase the events and actions that have been done on a file system in order. 
- **Modified (M)**: This holds the time when the content of the file was last changed. 
- **Accessed (A)**: This holds the time when the file was last accessed, read, or opened.
- **Changed (C)**: This holds the time when the MFT record changes. It has the time when the file was created, or if it was copied or moved somewhere.
- **Birthed (b)**: This is when the file was first instantiated, or created.

| Operation   | Modified       | Accessed | Birth (Created) |
| ----------- | -------------- | -------- | --------------- |
| File Create | Yes            | Yes      | Yes             |
| File Modify | Yes            | No       | No              |
| File Copy   | No (Inherited) | Yes      | Yes             |
| File Access | No             | No*      | No              |

These timestamps are stored in the `$MFT` file in the root system drive. These timestamps are placed in 2 attributes in the `$MFT`:
1. `$STANDARD_INFORMATION`: The timestamps in the windows explorer come from here.
2. `$FILE_NAME`

---
