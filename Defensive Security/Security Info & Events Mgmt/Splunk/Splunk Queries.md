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
### Detecting [[Kerberoasting]] - TGS Requests

```
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```
- This query is searching for all TGS requests that do not have a corresponding explicit credential logon in the same time window.
- It filters out the events where the username ends in a `$`, which signifies a computer account.
- `| rex field=user "(?<username>[^@]+)"`: Extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.

### Detecting [[Kerberoasting]] - TGS Transactions

```
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$ 
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769) 
| where closed_txn=0 AND EventCode = 4769
| table _time, EventCode, service_name, username
```
- `| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)`: Groups events into `transactions` based on the `username` field. The `keepevicted=true` option includes events that do not meet the transaction criteria. The `maxspan=5s` option sets the maximum time duration of a transaction to 5 seconds. The `endswith=(EventCode=4648)` and `startswith=(EventCode=4769)` options specify that transactions should start with an event with `EventCode 4769` and end with an event with `EventCode 4648`.
- `| where closed_txn=0 AND EventCode = 4769`: Filters the results to only include transactions that are not closed (`closed_txn=0`) and have an `EventCode` of `4769`.
- `| table _time, EventCode, service_name, username`: Displays the remaining events in tabular format with the specified fields.
- This query focuses on identifying events with an `EventCode` of `4769` that are part of an incomplete transaction (i.e., they did not end with an event with `EventCode 4648` within the `5`-second window).

---
### Detecting [[AS-REProasting]]

```
index=main source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```
- Review the above queries to understand the `spath` and `rename` lines.
- What this query does is that it filters only for user objects and for accounts with unconstrained delegation.

```
index=main source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```
- This query checks for TGT requests made for accounts with pre-authentication disabled.

---
### Detecting [[Pass the Hash]]

```
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

```
index=main (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```
- `(source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe")`: Filters the search to only include `Sysmon` operational log events with an `EventCode` of `10` (Process Access). It further narrows down the results to events where the `TargetImage` is `C:\Windows\system32\lsass.exe` (indicating that the `lsass.exe` process is being accessed) and the `SourceImage` is not a known legitimate process from the Windows Defender directory.
- `OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)`: Filters the search to also include Security event log events with an `EventCode` of `4624` (Logon), `Logon_Type` of `9` (NewCredentials), and `Logon_Process` of `seclogo`.

---
### Detecting [[Pass the Ticket]]

```
index=main source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```
- [[Kerberos]] TGS requests (`4769`) or ticket renewals (`4770`) happening _without_ a preceding TGT request (`4768`) from the same username + IP within 10 hours.
- `| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"`: This command extracts the IPv4 address from the `src_ip` field, even if it's originally recorded as an IPv6 address. It assigns the extracted value to a new field called `src_ip_4`.

---
### Detecting [[Overpass the Hash]]

```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```
- we are looking for all communication made by processes to the [[Domain Controller]] on [[Port]] 88 by a weird process name, that is not [[Windows Processes#`lsass.exe`|LSASS.exe]].
- Then, we use `eventstats` to combine the data about processes present in Event IDs 1 and 3, as event ID 3 does not contain all process related information, by matching on the `process_id`.
- We then keep only Event ID 3, we only used Event ID 1 to obtain the data about the processes, to show network connections.

---
