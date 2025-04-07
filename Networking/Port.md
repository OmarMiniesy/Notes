### General Notes

Used to identify a single network process on a machine.
- To identify a process on a network or machine: `<IP>:<port>`
- Daemons, or programs that run services, use ports.

> The port number is found in the header of the packets of TCP or UDP

To view the listening ports and the current TCP connections:
* `netstat -ano` Windows
* `netstat -tunp` Linux

---
### Well Known Ports

Ports between `0-1023` are called **the first 1024** and are well known ports. These are used by the most famous [[Protocol]]s, server processes, and famous daemons.
- [Famous Ports](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

Some famous ports:

| Service       | Port          |
| ------------- | ------------- |
| SMTP          | 25            |
| SSH           | 22            |
| POP3          | 110           |
| IMAP          | 143           |
| HTTP          | 80            |
| HTTPS         | 443           |
| NETBIOS       | 137, 138, 139 |
| SFTP          | 115           |
| TELNET        | 23            |
| FTP           | 20, 21        |
| RDP           | 3389          |
| MySQL         | 3306          |
| MS SQL SERVER | 1433, 1434    |
| SMB           | 445           |
| DNS           | 53            |
| DHCP Server   | 67            |
| DHCP Client   | 68            |

---
