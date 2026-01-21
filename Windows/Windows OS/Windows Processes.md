### General Notes

A process maintains and represents the execution of a program. A process has:
- *Virtual address space*: Virtual memory address for the process.
- *Executable code*: The code and data stored in the virtual address space.
- *Handles to system objects*: Open handles to system resources accessible by the process.
- *Security context*: Defined by the access token, which has the user for the process, the security groups, privileges, and integrity level.
- *Process Identifier*
- *Environment variables*
- *Priority class*
- *Min/Max working set sites*
- *At least 1 thread*: This is an executable unit deployed by the process. This is what controls the execution.

Windows processes can either run in *user mode* or *kernel mode* and it depends on the type of code being executed.

**User Mode** is for applications, and windows creates a process for these applications.
- These created processes come with a *private virtual address space* and a *private handle table*.
- Each application is running in isolation and applications cannot modify other application's data.
- These processes cannot access the virtual addresses of the operating system.

**Kernel Mode** is for core operating system components.
- Code in kernel mode all runs in a *single virtual address space*.
- As a result, kernel mode drivers and processes could cause OS level faults and crashes.

**Sessions** are a collection of process that represent a single user's session.
- Sessions are assigned unique IDs that are incremental starting from `1`.
- Session `0` is used for Windows system services and is isolated.

**DLLs**, or *Dynamic Link Libraries*, are files that contain code and data and can be used by more than one program.
- DLLs promotes modularized code and efficient memory usage.
- DLLs export function, and programs call these functions to use them.
- DLLs are assigned as dependencies when they are loaded into a program.

When *run-time dynamic linking* is used to load DLLs into a program, a function like `LoadLibrary` is used to load the DLL at run time. Then, `GetProcAddress` is needed to identify the exported DLL function to call.
- This technique is used by attackers.

---
##### `System` process

This process always has a `PID` of 4.
- Image Path : `C:\Windows\system32\ntoskrnl.exe`
- Parent Process : `System Idle Process (0)`
- There is only 1 instance of this process.
- Runs in *session* `0`.

##### `smss.exe` process

The `session manager subsytem` process (Windows Session Manager) is responsible for creating *sessions*.
- This is the first user mode process started, and it starts the user and kernel modes:
	- `win32k.sys` which is kernel mode.
	- `winsrv.dll` and `csrss.exe` which are for user mode.
- The process goes by first starting `csrss.exe` which is the windows subsystem and `winnit.exe` in *session 0*.
- Then it starts `csrss.exe` and `winlogon.exe` in *session 1* for the user session.
- This process is responsible for creating environment variables, virtual memory paging files, and starting the windows login manager (`winlogon.exe`).

The process has:
- Image Path : `%SystemRoot%\System32\smss.exe`
- Parent Process : `System (4)`
- 1 master instance and 1 child instance per session that exists after the session is created.
- User Account : local `SYSTEM`
- The start time should be very near (seconds) within the boot time of the master time instance.

##### `csrss.exe` process

The `Client Server Runtime Process` is the user mode of the Windows subsystem and it is always running.
- This process cannot be terminated.
- It is responsible for the Win32 console, process management, and loading `csrsrv.dll`, `basesrv.dll`, and `winsrv.dll`.
- There is one instance of it in every session, including session 0.
- Since `smss.exe` is the parent process and it self-terminates, there should be no parent process for this process.

The process has:
- Image Path : `%SystemRoot%\System32\csrss.exe`
- User Account : local `SYSTEM`
- The start time should be very near (seconds) within the boot time of the first 2 instances (session 0 and 1).

##### `wininit.exe`

The `Windows Initialization` process is responsible for launching `services.exe`, `lsass.exe`, and `lasiso.exe` all within *session 0*.
- `services.exe` is the *service control manager*.
- `lsass.exe` is the *local security authority*.
- `lsaiso.exe` is the *Credential Guard and KeyGuard*.

The process has:
- Image Path : `%SystemRoot%\System32\wininit.exe`
- No parent process, as `smss.exe` terminates.
- There should be only 1 instance.
- User Account : local `SYSTEM`
- The start time should be very near (seconds) within the boot time.

##### `services.exe`

The `Service Control Manager` (SCM) is used to handle system services like loading them, starting, and ending them.
- The SCM communicates with a  database that has information on the services through `sc.exe`.
- Information about services can also be found in the [[Windows Registry]]  `HKLM\System\CurrentControlSet\Services`.
- This process is the parent process to `svchost.exe`, `spoolsv.exe`, `msmpeng.exe`, and `dllhost.exe`.

This process is also responsible for setting the *Last Known Good Control Set* in the `HKLM\System\Select\LastKnownGood` [[Windows Registry]].
- This is a Windows feature that allows you to boot your computer using the registry settings from the last time Windows successfully started.

This process has:
- Image Path: `%SystemRoot%\System32\services.exe`
- Parent Process: `wininit.exe`
- There is only one instance and it is in `session 0`
- User Account: local `SYSTEM`
- Start time is within seconds of boot time.

##### `svchost.exe`

The *Service Host* process is responsible for hosting and managing Windows services. These Windows services are implemented as DLLs.
- The location of the DLLs that are to be implemented are stored in the [[Windows Registry]] for each service in the `Parameters` subkey in `ServiceDLL`.
```path
HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\Parameters
```

> Using [[Process Hacker]], right clicking on the `svchost.exe` process and choosing *Services*, then choosing the chosen service and going to it, we can see the path of the DLL that is used as well as the binary path with the `-k` flag which indicates a legitimate `svchost.exe` process.

This process has:
- Image Path: `%SystemRoot%\System32\svchost.exe`
- Parent Process: `services.exe`
- It has many instances, making it susceptible to attacks by malware to try and hide.
- It starts within seconds of boot time and other instances can start later.

##### `lsass.exe`

The *Local Security Authority Subsystem Service* is responsible for enforcing the security policy on the system by doing the following:
- Verifying user logins.
- Handling password changes.
- Creating access tokens.
- Writing to the Windows Security Log in the [[Windows Events Log]].
- Creating security tokens for Security Account Manager (SAM), Active Directory, and NETLOGON.
- It uses the authentication packages specified in `HKLM\System\CurrentControlSet\Control\Lsa`.

> SAM is a windows system database that stores user account information and security descriptors for the computer. Resides in `C:\Windows\System32\config\SAM`. It is in the [[Windows Registry]] under `HKEY_LOCAL_MACHINE\SAM`.

It has:
- Image Path : `%SystemRoot%\System32\lsass.exe`
- Parent Process : `wininit.exe`
- It has one instance and it starts within seconds of boot time.
- User Account : local `SYSTEM`
##### `winlogon.exe`

The *Windows Logon* process is responsible for 
- Handling the *Secure Attention Sequence*, or `CTRL+ALT+DELETE` key combination.
- Loading user profiles by loading the `NTUSER.DAT` into the `HKCU`, which is the [[Windows Registry#Registry Keys|Registry Key]] for the *Current User*.
- The `userinit.exe` process loads the user shell in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, which spawns `explorer.exe` and then exits.
- The lock screen and screen saver.

It has:
- Image Path : `%SystemRoot%\System32\winlogon.exe`
- Parent Process : Since i t is called by `smss.exe` which exits after it is done, there is no parent process.
- User Account : local `SYSTEM`.
- It has more than one instance, and the start time is within seconds of the start time of *session 1*.

##### `explorer.exe`

The *Windows Explorer* process is the process that gives user access to folders and files, the start menu, and the task bar.

It has:
- Image Path : `%SystemRoot%\explorer.exe`
- Parent Process : Since i t is called by `userinit.exe` which exits after it is done, there is no parent process.
- User Account : the logged in user.
- It has one instance per logged in user, and the start time of the first instance is at the first interactive login by a user.

---

