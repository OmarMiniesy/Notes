### Detecting [[Domain Reconnaissance]] using Native Windows Binaries

To detect the use of native windows binaries using [[Splunk]]:
```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```
- We filter on [[Sysmon]] event ID 1 for process creation.
- First we look at the `process_name` field, which only has the process name and not the whole command. This is used to filter out for known suspicious tools used for reconnaissance.
- Then, we also check for the `process_name` of PowerShell or CMD and check the entire `process` if it contains any of the tools again. This is because sometimes attackers can run these tools through them as a sort of evasion technique.
- Then, we do `stats` to start summarizing by the `parent_process` and its `pid`, and display the value of `process` for the filtered rows. We use `min(_time)` to return the earliest timestamp for the chosen parent process.
- Finally, we only show the rows where more than 3 `process` rows exist after we had grouped by `parent_process`. This is to output only when a single parent process has more than 3 `process` entries, meaning that this parent process executed 3 child processes.

---
### Detecting Recon by [[BloodHound]]

Utilizing some of the known filters used by [[Lightweight Directory Access Protocol (LDAP)]] for reconnaissance, we built the below query.

```
index=main source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```
- This works on [[Event Tracing for Windows (ETW)]] data collected via [[SilkETW]] into a [[Windows Events Log]] channel called `SilkService-Log`. Hence, this query is operating on LDAP ETW events.
- Silk writes the ETW payload into the `Message` field as JSON/XML. `spath` is used to parse structured fields from this data blob.
- Then, we flatten the ETW fields to change from  `XmlEventData.SearchFilter` to `SearchFilter` and so on, so we can use the fields directly by their name.
- We then sort by time using `0` to sort all fields in ascending order without the default limit of 10,000 rows being ordered.
- Then, we check that the field `SearchFilter` has the given data. This was obtained from the [[BloodHound#Detecting Bloodhound Usage|LDAP filters]]. This is used to enumerate domain users and build attack path graphs.
- Then, we aggregate the LDAP activity per host, process name, and process ID.
- Then, we filter for only the processes that issued more than 10 LDAP searches, which is indicative of malicious behavior. This step is looking for instances where the same process on the same computer made more than ten search queries with the specified filter condition.
- Finally, to make the `maxtime` human readable, we use the `ctime` function.

---
### Detecting [[Password Spraying]]

```
index=main source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, Failure_Reason
```
- This query selects events from the [[Windows Events Log]] Security channel and filters on [[Windows Events Log]] Event ID `4625` which is indicative of a failed login.
- Then, it creates time buckets of 15 minutes which is used to analyze trends over time.
- Then we aggregate all the events based on the `src` host, the source [[IP]] address, the `dest` host, and the `Failure_Reason`. This aggregation is used to filter the `user` field, which is the username, and the distinct count of these users per these 4 fields.
- This allows us to identify the usernames and the distinct count of usernames that had a failed log in attempt by the same source computer and the same destination computer. If we observe a lot of usernames, then this is indicative of password spraying.

---
