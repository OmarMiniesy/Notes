### General Notes

Explaining **user mode** and **kernel mode** then showcasing the flow of calling an API from user mode application.

---
### Modes of Operation

Windows operating system operates in *user mode* and in *kernel mode*.
##### User Mode

Where most applications and user processes operate.
- Apps here have limited access to system resources.
- Must interact with OS or system resources through *APIs* & *system calls*.
- [[Windows Processes]] here are isolated from each other.

User mode components include:
- *System Support Processes*: `winlogon.exe`, `smss.exe`, and `services.exe`. Check [[Windows Processes]] for details on these processes.
- *Service Processes*: These run in the background and run windows services like `Windows Update Service`, `Task Scheduler`, and `Print Spooler`.
- *User Applications*: These are processes started by user programs (both 32-bit and 64-bit). When a user application needs to interact with the operating system it calls the documented Windows APIs. These API calls get redirected to `NTDLL.DLL`, triggering a transition from user mode to kernel mode, where the system call gets executed. The result is then returned to the user-mode application, and a transition back to user mode occurs.
- *Subsystem DLLs*: These DLLs implement the high-level Windows APIs exposed to applications. They translate the documented API functions into calls to the native system call interface in `NTDLL.DLL`.  They prepare parameters, handle compatibility logic, and then route requests into `NTDLL.DLL`.
	- `kernelbase.dll` and `kernel32.dll` for process, thread, file, and memory management.
	- `user32.dll` for GUI and window management.
	- `advapi32.dll` for registry, security, and service-related APIs.
	- `wininet.dll` for high-level networking and [[HTTP]]/[[HTTPS]] functionality.

##### Kernel Mode

**Kernel Mode**: High privilege mode where the Windows kernel runs.
- Kernel has unrestricted access to system resources, hardware, and critical functions.
- Kernel also provides core OS services and manages system resources.
- *Device Drivers* which are used to communicate with hardware devices operate in kernel mode.

Kernel mode components include:
- *Executive Layer*: The upper portion of kernel mode that receives system calls once the transition from user mode occurs. When a system call is invoked, it is routed to this layer where the appropriate subsystem handles it:
	- `I/O Manager`
	- `Object Manager`
	- `Security Reference Monitor`
	- `Process Manager`
- *Kernel*: This component manages system resources, providing low-level services like *thread scheduling*, *interrupt and exception dispatching*, and *multiprocessor synchronization*. Kernel does not understand high level objects, it only understands low level.
- *Device Drivers*: These kernel mode software components enable the OS to interact with hardware devices. They serve as intermediaries, allowing the system to manage and control hardware and software resources.
	- Hardware drivers
	- File system drivers
	- Filter drivers
	- Virtual drivers
- *Hardware Abstraction Layer (HAL)*: This component provides an abstraction layer between the hardware devices and the OS. It allows software developers to interact with hardware in a consistent and platform-independent manner.

---
### Windows API Call Flow

1. **User Application Calls a Win32 API**  
	- The application calls a high-level API (e.g., `CreateFileW`, `RegOpenKeyEx`) exposed by subsystem DLLs like `kernel32.dll`, `advapi32.dll`, or `user32.dll`.
2. **Subsystem DLL Translates the API Call**  
    - The DLL validates parameters and translates the Win32 API into a **Native API** call (e.g., `NtCreateFile`) located in `ntdll.dll`.
3. **Subsystem DLL Calls the Native API in NTDLL.DLL**  
    - The call enters `ntdll.dll`, which contains the system call stubs responsible for transitioning into kernel mode.
4. **NTDLL Executes a System Call Stub (`syscall` instruction)**  
    - `ntdll.dll` loads the **system call number** into registers and executes the `syscall` instruction.  
    - This triggers a **user-mode → kernel-mode transition**.
5. **Kernel Mode Entry: System Service Dispatcher Begins Processing**  
    - The kernel’s entry point (e.g., `KiSystemServiceStart`) receives the call and extracts the **system call number** from the CPU registers.
6. **System Service Call Table (SSDT) Lookup Occurs**  
    - The kernel uses the system call number as an **index into the System Service Dispatch Table (SSDT)**.
    - The SSDT maps system call numbers → function pointers for kernel routines.
7. **The Kernel Executes the Target Function via the SSDT Pointer**  
    - The SSDT entry directs execution to the appropriate Windows Executive component
8. **Return Path: Hardware/Drivers → Executive → Kernel Dispatcher**  
    - After completing the work, the result flows back toward user mode through:  
    - Drivers → Executive → System Service Dispatcher.
9. **Kernel Returns to NTDLL.DLL (Kernel → User Transition)**  
    - The CPU switches back to user mode, and the result (success/failure, handles, data) returns to `ntdll.dll`.

---
