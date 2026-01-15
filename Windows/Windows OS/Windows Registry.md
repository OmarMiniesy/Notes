### General Notes

The windows registry is a *database* that stores *low level settings* for Windows. These settings include:
- Device configurations
- Security settings
- Services
- User account security configurations
- Recently used files and programs
- Devices connected to the system

> Can be viewed using the `regedit.exe` utility.

The registry stores information using two types of containers:
- **Registry keys** are objects similar to folders.
- **Registry values** are objects similar to files.

> The registry is stored in a number of disk files called *hives*.

Settings for individual users on a system are stored in a hive (disk file) for each user.
- During user login, the system loads the user hive whose location is stored in the `HKU` key, and then sets the value of the `HKCU` to that current user.
- Not all hives are loaded at any one time. At boot time, only a minimal set of hives are loaded, and after that, hives are loaded as the operating system initializes and as users log in or whenever a hive is explicitly loaded by an application.

---
### Registry Keys

A key is a container object similar to a Windows folder.
- Keys can contain other *subkeys* and *values*.
- Keys are referenced with a syntax similar to Windows paths, using backslashes `\` for hierarchies.

Keys at the top of the hierarchy are called *root keys*, and these have many sub keys. There are seven predefined root keys that are named according to constant handles defined in the *Win32 API*:
- `HKEY_CURRENT_USER` or `HKCU` - This contains the root configuration information for the user currently logged in. Contains information about folders, screen colors, control panel,..
- `HKEY_USERS` or `HKU` - This contains all the actively loaded user profiles on the computer.
- `HKEY_LOCAL_MACHINE` or `HKLM` - This contains configuration information for the computer.
- `HKEY_CLASSES_ROOT` or `HKCR` - This is a subkey of `HKLM\Software` and is used to ensure that the correct programs open when a file is opened by Windows Explorer.
- `HKEY_CURRENT_CONFIG` or `HKCC` - This contains information about the hardware profile used by computer on startup.
- `HKEY_PERFORMANCE_DATA`
- `HKEY_DYN_DATA`

---
### Registry Values

A value is a name/data pair that is stored inside a *registry key*.
- Each registry value can store arbitrary data with variable length and encoding.

Each registry value has a *symbolic type* associated with it that define how to parse this data, more like the data type of the value. 
- There are 11 standard symbolic types shown [here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types#:~:text=Registry%20value%20types,-Article).

---
### Accessing the Registry Hives

 The registry hives are also located on disk and are mostly present in the `C:\Windows\System32\Config` directory. There are files present in that directory, each pointing to a certain Hive.
 - `\DEFAULT` file appears in the registry as `HKEY_USERS\DEFAULT`
 - `\SAM` as `HKEY_LOCAL_MACHINE\SAM`
 - `\SECURITY` as `HKEY_LOCAL_MACHINE\Security`
 - `\SOFTWARE` as `HKEY_LOCAL_MACHINE\Software`
 - `\SYSTEM` as `HKEY_LOCAL_MACHINE\System`

For user information, there are 2 hives present at:
- `C:\Users\<username>\.NTUSER.DAT` which maps to `HKEY_CURRENT_USER`.
- `C:\Users\<username>\AppData\Local\Microsoft\Windows\.USRCLASS.DAT` which maps to `HKEY_CURRENT_USER\Software\CLASSES`.

> For more locations, check out [[Windows Forensics]].

These files are important to know in the case that a disk file is provided, so offline analysis will be performed not using `regedit.exe`.

---
### Transaction Logs & Backups

*Transaction logs* are the changelog of the registry hive, and they sometimes have the changes that are to be written in the hive itself.
- Transaction logs exist for each hive and are stored with  `.LOG` extension with the same name in the same directory as the hive.
- There can be multiple `.LOG` files with numbers.

*Registry backups* are the backups of the hives present in the `C:\Windows\System32\Config` directory.
- Copies of the hives are made every 10 days and are moved to the `\RegBack\` directory.

---
