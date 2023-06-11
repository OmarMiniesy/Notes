
### General Notes

> Framework used for penetration testing and exploit development.
> This is done in the exploitation phase of the penetration test.

> Using `msfconsole`:
1. Identify the vulnerable service.
2. Search for an exploit.
3. Load and configure the exploit.
4. Load and configure the payload.
5. Running the exploit and getting access to vulnerable machine.

> Mostly used to gain shells on target machines. Similar to [[Backdoors]].
> Use the [[Meterpreter]] payload to do that.

>Update metasploit frequently using `msfupdate`.

---

## Configuring the Attack Inside `msfconsole`

### Exploits

> Search for an exploit
```
search <search-string>
```

> Use an exploit
```
use <path-to-exploit>
```

> Viewing an exploits info and its options after using it.
```
info
show options
```

>Configuring an exploit after using it.
```
set <option-name> <option-value>
```


### Payloads

> After choosing and configuring the exploit, we can set the payload.
> `show payloads` shows all the available payloads for that set exploit.

>To set a payload
```
set payload <path-to-payload>
```

> To view and configure same as for exploits.

---

## Running an Exploit

> Using the command `exploit` or `run`.

---
