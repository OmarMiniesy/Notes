### General Notes

This is a tool designed to pinpoint security threats in [[Windows Events Log|Windows Event Logs]] through integration with [[Sigma]] detection rules and custom Chainsaw rules.
- It uses keyword based searching.

> Official Chainsaw GitHub [repo](https://github.com/WithSecureLabs/chainsaw).

---
### Using Chainsaw

After downloading chainsaw from the GitHub repo, we can use the `-h` flag to check out the available commands and options.

To run Chainsaw against a target file and use Sigma detection rules, we can write the following command:
```powershell
.\chainsaw.exe hunt <path\to\target\.evtx> -s <path\to\sigma\files> --mapping .\mappings\sigma-event-logs-all.yml 
```
- Use the `hunt` option to look for threats in the target `evtx` using the specified sigma detection rules.
- Use the `-s` to pinpoint the Sigma detection rule file or directory.
- Use the `--mapping` with the given file to map the fields in the sigma files to the fields in the `evtx` log file.

---
