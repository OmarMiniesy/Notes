### General Notes

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

---
##### `System` process

This process always has a `PID` of 4.
- `Image Path` : `C:\Windows\system32\ntoskrnl.exe`
- `Parent Process` : `System Idle Process (0)`
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
- `Image Path` : `%SystemRoot%\System32\smss.exe`
- `Parent Process` : `System (4)`
- 1 master instance and 1 child instance per session that exists after the session is created.
- `User Account` : local `SYSTEM`
- The start time should be very near (seconds) within the boot time of the master time instance.

##### `csrss.exe` process

The `Client Server Runtime Process` is the user mode of the Windows subsystem and it is always running.
- This process cannot be terminated.
- It is responsible for the Win32 console, process management, and loading `csrsrv.dll`, `basesrv.dll`, and `winsrv.dll`.
- There is one instance of it in every session, including session 0.
- Since `smss.exe` is the parent process and it self-terminates, there should be no parent process for this process.

The process has:
- `Image Path` : `%SystemRoot%\System32\csrss.exe`
- `User Account` : local `SYSTEM`
- The start time should be very near (seconds) within the boot time of the first 2 instances (session 0 and 1).

##### `wininit.exe`

The `Windows Initialization Process` is responsible for launching `services.exe`, `lsass.exe`, and `lasiso.exe` all within *session 0*.
- `services.exe` is the *service control manager*.
- `lsass.exe` is the *local security authority*.
- `lsaiso.exe` is the *Credential Guard and KeyGuard*.

The process has:
- `Image Path` : `%SystemRoot%\System32\wininit.exe`
- No parent process, as `smss.exe` terminates.
- There should be only 1 instance.
- `User Account` : local `SYSTEM`
- The start time should be very near (seconds) within the boot time.

##### `services.exe`

The `Service Control Manager` (SCM) is used to handle system services like loading them, starting, and ending them.
- The SCM communicates with a  database that has information on the services through `sc.exe`.
- Information about services can also be found in the [[Windows Registry]]  `HKLM\System\CurrentControlSet\Services`.

