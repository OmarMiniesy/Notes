### Using [[Wireshark]]

The following showcases how to determine if [[nmap]] is being used through [[Wireshark]].
###### [[Transport Layer#TCP|TCP]] Connect Scan
To detect the *TCP Connect Scan*, or the [[Transport Layer#Three Way Handshake|3 way handshake]], we need to look for the following packet sequences:
- For open TCP [[Port]]s:
	1. Client sends `SYN`
	2. Server sends `SYN,ACK`
	3. Client sends`ACK`
	4. Client sends `RST,ACK` (on termination)
- For closed TCP Ports:
	1. Client sends `SYN`
	2. Server sends `RST,ACK` (to terminate)

> The connect scan has a `windows size` *larger than 1024 bytes* as the request expects some data due to the nature of the protocol.

We can write a display filter to check for the initiation of a TCP connect scan. Check [[#Nice Wireshark Display Filters]] for more guidance.
```wireshark
tcp.flags.syn == 1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

###### TCP SYN Scan
The *TCP SYN Scan* does not use the 3-way handshake, but can be detected using the follow packet sequences:
- For open TCP [[Port]]s:
	1. Client sends `SYN`
	2. Server sends `SYN,ACK`
	3. Client sends `RST` (on termination)
- For closed TCP Ports:
	1. Client sends `SYN`
	2. Server sends `RST,ACK` (to terminate)

> The connect scan has a `windows size` *smaller than 1024 bytes* as the request is not finished and it doesn't expect to receive data.

We can write a display filter to check for the initiation of a SYN connect scan. Check [[#Nice Wireshark Display Filters]] for more guidance.
```wireshark
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

###### [[Transport Layer#UDP|UDP]] Scans
UDP scans don't use the handshake process and there is no response from open ports, however, there is an [[ICMP]] error message returned for closed ports.
- Client sends UDP packet.
- Server responds with *ICMP Type 3, Code 3 Destination Unreachable, Port Unreachable*.

To check for these ICMP packets, run this display filter. Check [[ICMP#ICMP Packet|ICMP Codes & Types]] for more information.
```wireshark
icmp.type == 3 and icmp.code == 3
```

> The ICMP packet sent as a response will contain the original UDP packet sent encapsulated in the ICMP payload.

###### Nice Wireshark Display Filters

| **Notes**                                                                                        | **Wireshark Filters**                                                          |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| - Only `SYN` flag.<br>- `SYN` flag is set. The rest of the bits are not important.               | - `tcp.flags == 2`<br><br>- `tcp.flags.syn == 1`                               |
| - Only `ACK` flag.<br>- `ACK` flag is set. The rest of the bits are not important.               | - `tcp.flags == 16`<br><br>- `tcp.flags.ack == 1`                              |
| - Only `SYN`, `ACK` flags.<br>- `SYN` and `ACK` are set. The rest of the bits are not important. | - `tcp.flags == 18`<br><br>- `(tcp.flags.syn == 1) and (tcp.flags.ack == 1)`   |
| - Only `RST` flag.<br>- `RST` flag is set. The rest of the bits are not important.               | - `tcp.flags == 4`<br><br>- `tcp.flags.reset == 1`                             |
| - Only `RST`, `ACK` flags.<br>- `RST` and ACK `are` set. The rest of the bits are not important. | - `tcp.flags == 20`<br><br>- `(tcp.flags.reset == 1) and (tcp.flags.ack == 1)` |
| - Only `FIN` flag<br>- `FIN` flag is set. The rest of the bits are not important.                | - `tcp.flags == 1`<br><br>- `tcp.flags.fin == 1`                               |

> For something to not be set, we change from `1` to `0`.

---
