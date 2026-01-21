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

- `.text`: contains code and and entry point.
- `.data`: contains global variables and initialized data.
- `.rdata` `.idata`: contains imports
- `.reloc`: contains relocation information
- `.rsrc`: contains application resources like images or icons.
- `.debug`: contains debug information

---
### Tools

The tool `pecheck` can be used to analyze the header of PE files.
- Very useful for [[Static Analysis]] of [[Malware]].

```
pecheck <file-name>
```

The tool `pestudio` is also very nice.

---
