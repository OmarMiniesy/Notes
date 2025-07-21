### General Notes

The windows registry is a *database* that stores *low level settings* for Windows. These settings include:
- Device configurations
- Security settings
- Services
- User account security configurations

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
- `HKEY_LOCAL_MACHINE` or `HKLM`
- `HKEY_CURRENT_CONFIG` or `HKCC`
- `HKEY_CLASSES_ROOT` or `HKCR`
- `HKEY_CURRENT_USER` or `HKCU`
- `HKEY_USERS` or `HKU`
- `HKEY_PERFORMANCE_DATA`
- `HKEY_DYN_DATA`

---
### Registry Values

A value is a name/data pair that is stored inside a *registry key*.
- Each registry value can store arbitrary data with variable length and encoding.

Each registry value has a *symbolic type* associated with it that define how to parse this data, more like the data type of the value. 
- There are 11 standard symbolic types shown [here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types#:~:text=Registry%20value%20types,-Article).

---
