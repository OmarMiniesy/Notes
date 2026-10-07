### General Notes

A *LNK file* (`.lnk`) is a Windows shortcut — a small file that points to another file, program, or folder so you can launch it without going to its real location.
- Double-clicking a shortcut just runs whatever it points at. The shortcut itself isn't the program; it's a pointer plus some saved settings (icon, working folder, and the command to run).
- Windows often hides the `.lnk` extension and shows the shortcut's icon instead, so a shortcut can be made to look like a PDF, document, or folder.

---
### The Target Field

Every shortcut has a *Target* field: the command Windows runs when the shortcut is opened. 
- For a normal shortcut this is just a path, e.g. `C:\Windows\System32\notepad.exe`.

The target isn't limited to a plain path — it can include a program **plus arguments**. 
- An attacker points it at a trusted built-in tool and passes it instructions, e.g.:
```
powershell.exe -w hidden -c "<commands>"
```

---









