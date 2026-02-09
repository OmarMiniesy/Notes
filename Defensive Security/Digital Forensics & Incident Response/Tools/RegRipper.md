### General Notes

This is a command line utility used in extracting information from the [[Windows Registry]] for [[DFIR]].
- The [GitHub repo](https://github.com/keydet89/RegRipper4.0).
- Check out [[Windows Registry Forensics]] for information on what data to extract from the registry and from where.

RegRipper automates the extraction of forensic data from registry hives, and applies *plugins*.
- Plugins are scripts that know what to extract from the registry and its full location, including the associated hive and the necessary key.

##### Nice Plugins

| Plugin Name    | Hive         | Hive Location                 | Description                                                                   |
| -------------- | ------------ | ----------------------------- | ----------------------------------------------------------------------------- |
| `compname`     | `SYSTEM`     | `C:\Windows\System32\config\` | Computer Name                                                                 |
| `timezone`     | `SYSTEM`     | `C:\Windows\System32\config\` | Timezone Information                                                          |
| `nic2` / `ips` | `SYSTEM`     | `C:\Windows\System32\config\` | Network Information, including [[Dynamic Host Configuration Protocol (DHCP)]] |
| `installer`    | `SOFTWARE`   | `C:\Windows\System32\config\` | Information about installed software                                          |
| `recentdocs`   | `NTUSER.DAT` | `C:\Users\<user-name>\`       | Recently accessed folders and documents.                                      |
| `run`          | `NTUSER.DAT` | `C:\Users\<user-name>\`       | Information about AutoStart run key entries.                                  |

---
### Using RegRipper

To enumerate the available plugins that can be used by RegRipper:
```powershell
.\rip.exe -l -c > rip_plugins.csv
```

To use RegRipper to extract any data, we need to provide the location of the needed artifact by specifying the target *Hive*, and we need to specify the *plugin* name.
```powershell
,\rip.exe -r "<path-to-registry>" -p <plugin-name>
```

---