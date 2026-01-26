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

1. *DOS Header*: This has the file type. It has the magic bytes `MZ` hex for `.exe` files, and it allows tools to recognize the file as an executable.
2. *DOS Stub*: This prints the message `This program cannot be run in DOS mode` if it is run in DOS. This is its only use.
3. *PE File Header*: This marks the start of the PE format, and it contains the file format, the signature and file header, and other important headers. It is identified by the `PE` hex.
4. *Optional Header*: Defines how the file is mapped in memory, contains the entry point, the image base, section alignment, size of the image, and DLL characteristics.
5. *Data Dictionaries*: Part of the optional header and they point to important tables.
6. *Section Table*: Defines the available sections and information present in the file. A section stores the content of a file, such as code, imports, or data.

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

The tool `pecheck` can be used to analyze the header of PE files.
- Very useful for [[Static Analysis]] of [[Malware]].

```
pecheck <file-name>
```

The tool `pestudio` is also very nice.

The tool `x64dbg` is also nice.

---
