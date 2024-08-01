
### General Notes

> The File Transfer Protocol (FTP) is a standard communication [[protocol]] used to transfer computer files from a server to a client on a computer network.

> Listens on [[Port]] 21. Check through [[nmap]] in the [[Footprinting and Scanning]] phase. Use with `-sC` script to see if anonymous login is supported: `ftp-anon`.

> SFTP for the secure version of FTP

---

> Can login using username `anonymous` when no username is specified. 
```
ftp anonymous@<ip-address>
```
> when asked for password just press enter.

---

> To download a file from inside the FTP service and use/read it
```
get <filename>
```
> Can now access it on the machine.

---
