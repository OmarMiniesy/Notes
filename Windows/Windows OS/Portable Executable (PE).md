### General Notes

This is a file format used to store and load executable code.
- It contains headers that tell Windows how to deal with the file, map it to memory, and run it.
- This includes `.exe`, `.dll`, `.sys`, and some `.ocx`.

The PE layout is composed of the *Header* and the *Sections*.

PE files rarely contain all of the code that they need to run on their own. 
- They use *imports* to import certain functions provided by Windows OS. This is indicative of the behavior that will be examined by that file. Check out [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/api/_winprog/) for the functions available.
- They also use *exports*, such that other files can use the functions they provide. This is usually the case with *dlls*.

---
#### **Header**

This contains the metadata about the PE file.
- PE headers are *STRUCT*s, and the documentation for each header can be found on [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)

The first 2 headers are:
1. *DOS Header*: This has the file type. It has the magic bytes `4D 5A` which translate to `MZ` in ASCII for `.exe` files, and it allows tools to recognize the file as an executable.
	- The last value stored here is the `e_lfanew` and it has the address of where the *IMAGE_NT_HEADERS* start.
2. *DOS Stub*: This prints the message `This program cannot be run in DOS mode` if it is run in DOS. This is its only use.

*IMAGE_NT_HEADERS*:
1. *PE File Header*: This marks the start of the PE format, and it contains the file format, the *signature* and *file header*, and other important headers. 
	- The *signature header* is identified by the `PE` ASCII or `50 45 00 00` in hex.
	- The *file header* has information about the type of machine compatible, the number of sections present, the time and date of the binary compilation, the size of the optional header, and characteristics about the PE file.
2. *Optional Header*: Defines how the file is mapped in memory, contains the entry point, the image base, section alignment, size of the image, and DLL characteristics.
	- _Magic:_ The Magic number tells whether the PE file is a 32-bit or 64-bit application. If the value is `0x010B`, it denotes a 32-bit application; if the value is `0x020B`, it represents a 64-bit application.
	- _AddressOfEntryPoint:_ This is the address from where Windows will begin execution. In other words, the first instruction to be executed is present at this address. This is a Relative Virtual Address (RVA), meaning it is at an offset relative to the base address of the image (*ImageBase*) once loaded into memory.
	- *BaseOfCode* and *BaseOfData*: These are the addresses of the code and data sections, respectively, relative to *ImageBase*.
	- _ImageBase:_ The ImageBase is the preferred loading address of the PE file in memory. Generally, the ImageBase for .exe files is 0x00400000. Since Windows can't load all PE files at this preferred address, some relocations are in order when the file is loaded in memory. These relocations are then performed relative to the ImageBase.
	- _Subsystem:_ This represents the Subsystem required to run the image. The Subsystem can be Windows Native, GUI (Graphical User Interface), CUI (Commandline User Interface), or some other Subsystem. The complete list in [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) with their values.
	- _DataDirectory:_ Contains import and export information of the PE file (called Import Address Table and Export Address Table).
	- *Data Dictionaries*: Part of the optional header and they point to important tables.

*IMAGE_SECTION_HEADER*:
4. *Section Table*: Defines the available sections and information present in the file. A section stores the content of a file, such as code, imports, or data. Some important information stored for each section:
	- _VirtualAddress:_ This field indicates this section's Relative Virtual Address (RVA) in the memory.
	- _VirtualSize:_ This field indicates the section's size once loaded into the memory.
	- _SizeOfRawData:_ This field represents the section size as stored on the disk before the PE file is loaded in memory.
	- _Characteristics:_ The characteristics field tells us the permissions that the section has. For example, if the section has READ permissions, WRITE permissions or EXECUTE permissions.

*IMAGE_IMPORT_DESCRIPTOR*:
- Contains information about the imported functions used from DLLs.

#### **Sections** (Actual Content)

A PE file is divided into sections, each with a different purpose.

- `Text Section (.text)`: The hub where the executable code of the program resides.
- `Data Section (.data)`: A storage for initialized global and static data variables.
- `Read-only initialized data (.rdata)`: Houses read-only data such as constant values, string literals, and initialized global and static variables.
- `Exception information (.pdata)`: A collection of function table entries utilized for exception handling.
- `BSS Section (.bss)`: Holds uninitialized global and static data variables.
- `Resource Section (.rsrc)`: Safeguards resources such as images, icons, strings, and version information.
- `Import Section (.idata)`: Details about functions imported from other DLLs.
- `Export Section (.edata)`: Information about functions exported by the executable.
- `Relocation Section (.reloc)`: Details for relocating the executable's code and data when loaded at a different memory address.

---
### Tools

These tools are used to analyze the headers of PE files and are very useful for [[Static Analysis]] of [[Malware]]:
- `pecheck`
- `pestudio`
- `x64dbg`
- `pe-tree`

---
