
### General Information

> Exploiting a windows machine through vulnerable authentication to administrative shares.
> Lets an attacker connect to a local or remote share.

> Not against any share. Those that have IPC, or the file server and printer sharing service.
> First test by using [[nmap]] to check the [[Port]]s: 135, 139, 445 running [[Server Message Block (SMB)]] [[Protocol]] or NETBIOS [[Transport Layer]] [[Protocol]].

---

## Enumeration and Checking for Null Sessions

### `nbstat` and `NET VIEW` for windows

> Disaply information about target's shares.
```
nbstat -A <ip-address>
```
> Ouput:
1. `<00>` record type means that this is a workstation.
2. `UNIQUE` means only 1 [[IP]] address.
3. `<20>` record type means that file sharing service is running for this machine.

> Once the code `<20>` is witnessed, then we can enumerate shares using `NET VIEW`.
```
NET VIEW <ip-address>
```
> The shares are then displayed.

##### Connect to share
> To check if they are vulnerable to null sessions we try to connect to a share using empty credentials.
```
NET USE \\<ip-address>\<share-name> '' /u:''
```
> Include the `$` sign if there is.


### `nmblookup` for linux

> To enumerate the shares of a target machine
```
nmblookup -A <ip-address>
```


### `smbclient` for linux

> Better than `NET VIEW` because it displays hidden administrative shares.

> Enumerate shares of a target machine. 
```
smbclient -L //<target-ip> -N
```
* `-L` to enumerate services.
* `-N` forces to not ask for password.

##### Connect to share
> Check if there are null sessions. Some can work, and some might not. 
```
smbclient //<ip-address>/<share-name> -N
```
> Include the `$` sign if there is.

---

## Exploiting Null Sessions

### `enum` for windows

> Retrieve information from a system vulnerable to null sessions.

> To enumerate the shares of a machine
```
enum -S <ip-address>
```

> To enumerate the users of a machine
```
enum -U <ip-address>
```

> To check the password policy of a machine
```
enum -P <ip-address>
```


### `enum4linux` for linux

> Similar to `nmblookup`, printing services and machine information.
```
enum4linux -n <ip-address>
```

> To enumerate the password policy
```
enum4linux -P <ip-address>
```

> To enumerate shares
```
enum4linux -S <ip-address>
```

> To do everything use the `-a` flag.
```
enum4linux -a <ip-address>
```

---

### Extra Info

> Check the permissions of available shares
```
smbmap -H <ip-address>
```

#### Using `nmap` scripts

> To enumerate shares use `--script=smb-enum-shares`.
> To enumerate users use `--script=smb-enum-users`.
> To brute force the user passwords use `--script=smb-brute`.
> To check vulnerabilities use `--script=smb-check-vulns`.

### `smbclient` commands

> Download a file
```
get <filename>
```

---
