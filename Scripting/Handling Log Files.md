### General Notes

I wanted to come up with some sort of plan for investigating log files, following a structured approach to identify the necessary data to be able to properly filter.

---
#### Obtain List of Providers

1. Created a lightning fast PowerShell script that parses the *Providers* from the `.evtx` file.
```powershell
.\list-providers.ps1 <sourcelogfile.evtx> <outputproviderlist.txt>
```

2. Run a Python script on the output text file to output only the providers in a unique list and sorted.
```
python3 unique-providers <outputproviderlist.txt> <uniqueproviderlist.txt>
```


---