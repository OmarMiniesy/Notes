
# Mapping a Network

## 1. Ping Sweeping

Sends [[ICMP]] packets (echo request), if the host is alive, replies with ICMP echo reply packets.
- They can perform this test on all the hosts alive on a network

#### `fping`

`fping` better than `ping`

```
fping -a -g <ip-address> 
```
- `-a` only to show the alive hosts
- `-g` to perform ping sweeps instead of normal pings
- The `ip-address` can be in CIDR notation or by specifying start and end addresses.

> For offline hosts, it shows error message: `ICMP Host unreachable`
- To suppress error messages, add to the end `2>/dev/null`

#### [[nmap]]

Can be used to perform ping sweeps using the `-sn` flag
- Specify the [[IP]] addresses using CIDR or as a range or using wildcards.

## 2. OS Fingerprinting

After the network is mapped with the alive hosts, we need to detect if they are [[Networking/Routing]] routers, servers, or clients.
- Do this by anaysing the response packets we get.
- A signature is created for the different hosts, and is compared to known ones in a database.

#### [[nmap]]

Can be used to perform OS discovery using the `-O` flag.
```
nmap -O -Pn <ip-address>
```
- Also add the `-Pn` flag to skip the ping discovery phase.
- The fingerprinting can be tuned to be aggressive or light.

---

# [[Port]] Scanning with [[nmap]]

- To discover the daemons and services running on the hosts.
- To discover which [[Transport Layer]] protocol is used: `TCP` or `UDP`

> Port scanners can identify if [[Firewall]]s exist

`nmap` scans by default the most famous ports
- To specify ports, use the `-p` flag.
- For all ports, use `-p-` flag. Use `--min-rate <num>` to speed up as num goes higher.

Can also add scripts that can find out more information about the targets.
- To use the default scripts to get more information: `-sC`.

There are multiple types of scans conducted by `nmap`: 

#### 1. TCP CONNECT SCAN `-sT`

##### Open Ports

Scanners work by completing the 3 way handshake for `TCP`.
- If the handshake completes, then the port is open. Otherwise it is closed.

##### Closed Ports 

Server replies with a packet that has `RST` reset and `ACK` acknowledge flags enabled
- This tells the client that is scanning that this port is closed.

#### 2. TCP SYN Scan `-sS`

TCP connect scan lets the daemons being scanned now they are being scanned, and gets recorded in its logs. So the `TCP SYN` scan is used to be stealthy.
- The `TSP SYN` scan doesn't complete the whole handshake, it only sends the `SYN` packet.

##### Open Ports

Scanner send the `SYN` packet, if the scanner receives the `ACK` packet then the port is open
- It then closes the connection by sending a `RST` package.

##### Closed Ports

If the scanner receives the `RST` packet, then the port is closed.

#### 3. Version Detection Scan `-sV`

Used to detect which applications are listening on the ports and detect their versions
- Does this by analyzing the banner for the daemon operating at that port.
- Works the same way as the TCP Connect, but then requests the banner and then closes the connection.

#### False Positives and Firewalls.

Incomplete results:
- Can use the `--reason` flag to check out more info.

> Seeing `tcpwrapped`, meaning that the host closed the TCP connection without sending data.

---

