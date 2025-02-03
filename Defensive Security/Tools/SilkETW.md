### General Notes

This is a tool that is used to interact with [[SilkETW]] in a simple interface.

- To specify the tracing mode, that is either user mode or kernel mode, use the `-t` flag followed by the mode.
```
silkETW.exe -t user
```

- To specify the provider name to trace, use the `-pn` flag followed by the name.
```
silkETW.exe -t user -pn Microsoft-Windows-Kernel-Process
```

- To specify that the output be written to a file with a chosen path use `-ot file -p <path>`.
```
silkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```

> SilkETW logs can be integrated with *event viewer* through `silkservice`. 

---
