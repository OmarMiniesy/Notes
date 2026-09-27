### General Notes

Practical guidance on how to detect [[Data Exfiltration]] attacks.

---
### Detecting [[Domain Name System (DNS)]] Exfiltration

Attackers utilize DNS Tunnelling to perform exfiltration using DNS. This is because:
- DNS lookups are routine and allowed outbound.
- DNS queries look benign unless they are closely expected.
- Data can be encoded in the DNS payload easily in the subdomain or the TXT responses.

To detect exfiltration, we should look for:
- Many DNS queries are sent to a single external domain, especially with very high counts compared to the baseline.
- Long subdomain labels or unusually long full query names (> 60–100 characters).
- High entropy or Base32/Base64-like patterns in the query name (lots of mixed case letters, digits, `-`, `=` signs for base64).
- Rare record types (`TXT`, `NULL`) or many large `TXT` responses.
- Unusual response behavior: frequent `NXDOMAIN` or TCP/large UDP fragments for DNS.
- Queries at regular intervals (beaconing behavior).

##### Using [[Wireshark]]

We can run the below query to check for DNS exfiltration:
```
dns && dns.flags.response == 0
```
- This searches for DNS queries being sent.
- We can then look for abnormal query length and domain names.

We can run the query below to check for large queries:
```
dns && frame.len > 70
```

---
### Detecting [[File Transfer Protocol (FTP)]] Exfiltration

Attackers can use FTP to exfiltrate data as it is used to transfer files over TCP/IP.
- They can do so using compromised credentials, non-standard [[Port]]s, misconfigured servers, and temporary accounts.

> Check out [[Investigating FTP]] and [[File Transfer Protocol (FTP)]] to better understand FTP commands.

To detect FTP exfiltration, look for:
- `USER` and `PASS` commands, this shows cleartext credentials.
- `STOR` and `RETR` commands, which are upload and download respectively.
- Large data connections to external [[IP]]s
- Passive FTP connections with data moving on ephemeral (temporary) ports.

##### Using [[Wireshark]]

We can look for the commands we have stated above using this syntax:
```
ftp.request.command == "USER" || ftp.request.command == "PASS"
```
- From here we can find usernames/passwords supplied and what the sessions do by following their TCP streams.

We can also drill down by looking for `stor` commands to look for weird files and large file sizes.
```
ftp contains "STOR"
```
- From here we can also follow TCP streams.

Looking for large file sizes:
```
ftp && frame.len > 90
```