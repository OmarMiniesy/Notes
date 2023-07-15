
### General Notes

> Dynamic websites can include other pages based on some parameters such as:
1. [[HTTP]] requests containing GET and POST.
2. [[Cookies]].

> Common file names present on most domains and systems. [List](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt).

---

### Local File Inclusion (LFI)

> Include a file into a website that wasn't intended to occur.

> Can be done if a website is using paths to include files. 
> If these paths are not sanitized, an attacker can play with the path and use the `../` string to view other files on the system.

---

### Remote File Inclusion (RFI)

> Similar to LFI but loading remote files through other [[Protocol]]s such as [[HTTP]] or [[File Transfer Protocol (FTP)]].

---

