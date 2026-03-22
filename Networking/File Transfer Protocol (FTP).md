### General Notes

The *File Transfer Protocol* (FTP) is a standard application layer [[protocol]] used to transfer computer files from a server to a client on a computer network.
- FTP is insecure by design, a newer protocol SFTP is used for its security.
- FTP supports user authentication, and an *anonymous login* option is allowed.

FTP operates using a client-server architecture on a single connection, while utilizing the *TCP* [[Transport Layer]] protocol.
- [[Port]] 20 is used for data transfer, and Port 21 is used for sending commands.

> A list of all the FTP [response codes](http://en.wikipedia.org/wiki/List_of_FTP_server_return_codes).

There are 2 modes of operation for FTP:
- *Active*: Default mode where the server listens for commands from the client. The client specifies the port to use for data transfer using `PORT` command.
- *Passive*: Used to access servers located behind [[Firewall]]s preventing TCP connections. The client sends the `PASV` command and waits for server to respond with [[IP]] and port to use for data transfer.

|**Command**|**Description**|
|---|---|
|`USER`|specifies the user to log in as.|
|`PASS`|sends the password for the user attempting to log in.|
|`PORT`|when in active mode, this will change the data port used.|
|`PASV`|switches the connection to the server from active mode to passive.|
|`LIST`|displays a list of the files in the current directory.|
|`CWD`|will change the current working directory to one specified.|
|`PWD`|prints out the directory you are currently working in.|
|`SIZE`|will return the size of a file specified.|
|`RETR`|retrieves the file from the FTP server.|
|`QUIT`|ends the session.


---
### Using FTP

Can login using username `anonymous` when no username is specified. 
```
ftp anonymous@<ip-address>
```
- when asked for password just press enter.

> Check through [[nmap]] in the [[Footprinting and Scanning]] phase. Use with `-sC` script to see if anonymous login is supported: `ftp-anon`.

To download a file from inside the FTP service and use/read it.
```
get <filename>
```

---
