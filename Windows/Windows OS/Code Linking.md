### General Notes

Windows executables need to use functions that are defined in external code libraries (like `kernel32.dll` or `ntdll.dll`). Instead of rewriting that code, programs *import* those functions and link to the library.

- An **import** is a function that a program uses but doesn't define itself — it comes from an external library.
- **Linking** is the mechanism that connects a program to the library containing that function.
- On Windows, these libraries are **DLL files** (Dynamic Link Libraries).

There are three types of linking:
- *Static Linking*
- *Dynamic Linking*
- *Runtime Linking*

---
### Static Linking

The library's code is copied directly into the executable at **compile time**.

- The final `.exe` is self-contained — it doesn't depend on external DLLs at runtime.
- Downside: the executable is larger, and if the library is updated, the program must be recompiled to get the fix.
- Common in portable tools or environments where DLL availability can't be guaranteed.

---
### Dynamic Linking

The program declares which DLL functions it needs, and Windows loads the DLL and resolves those functions **when the program starts**.

- The imports are visible in the PE (Portable Executable) header under the **Import Address Table (IAT)**.
- When the function is called, execution jumps into the DLL — the code runs inside the library, not the executable.
- Multiple programs can share the same DLL in memory, saving resources.
- Downside: if the required DLL is missing or the wrong version, the program fails to start.

This is the default linking method for most Windows programs.

---
### Runtime Linking

The program doesn't declare its imports upfront. Instead, it manually loads a DLL and resolves function addresses **while running**, using:
- `LoadLibrary()` — loads a DLL into the process.
- `GetProcAddress()` — retrieves the address of a specific function in that DLL.

Because the imports aren't declared in the IAT, [[Static Analysis]] tools won't see them. This makes it a common technique in [[Malware]] (especially packed or obfuscated samples) to hide what functions they're using.

---
