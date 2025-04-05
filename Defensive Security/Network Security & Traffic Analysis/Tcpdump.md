### General Notes

A command line packet sniffing tool that is used for [[Network Analysis]].
- It can operate in *promiscuous* mode to listen for all packets in the network, even if they are not destined for it. It can also work on saved `pcap` files.
- Requires root privileges to execute.

> Tcpdump will resolve [[IP]]s to hostnames by default.

---
### Using Tcpdump

|**Filter**|**Result**|
|---|---|
|host|`host` will filter visible traffic to show anything involving the designated host. Bi-directional|
|src / dest|`src` and `dest` are modifiers. We can use them to designate a source or destination host or port.|
|net|`net` will show us any traffic sourcing from or destined to the network designated. It uses / notation.|
|proto|will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)|
|port|`port` is bi-directional. It will show any traffic with the specified port as the source or destination.|
|portrange|`portrange` allows us to specify a range of ports. (0-1024)|
|less / greater "< >"|`less` and `greater` can be used to look for a packet or protocol option of a specific size.|
|and / &&|`and` `&&` can be used to concatenate two different filters together. for example, src host AND port.|
|or|`or` allows for a match on either of two conditions. It does not have to meet both. It can be tricky.|
|not|`not` is a modifier saying anything but x. For example, not UDP.|

| **Switch Command** | **Result**                                                                                                                                            |
| :----------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
|         D          | Will display any interfaces available to capture from.                                                                                                |
|         i          | Selects an interface to capture from. ex. -i eth0                                                                                                     |
|         n          | Do not resolve hostnames.                                                                                                                             |
|         nn         | Do not resolve hostnames or well-known ports.                                                                                                         |
|         e          | Will grab the ethernet header along with upper-layer data.                                                                                            |
|         X          | Show Contents of packets in hex and ASCII.                                                                                                            |
|         XX         | Same as X, but will also specify ethernet headers. (like using Xe)                                                                                    |
|     v, vv, vvv     | Increase the verbosity of output shown and saved.                                                                                                     |
|         c          | Grab a specific number of packets, then quit the program.                                                                                             |
|         s          | Defines how much of a packet to grab.                                                                                                                 |
|         S          | change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101)                                    |
|         q          | Print less protocol information.                                                                                                                      |
|         A          | Show only the ASCII text after the packet line                                                                                                        |
|        `l`         | will line buffer instead of pooling and pushing in chunks. It allows us to send the output directly to another tool such as `grep` using a pipe `\|`. |
|    r file.pcap     | Read from a file.                                                                                                                                     |
|    w file.pcap     | Write into a file                                                                                                                                     |

---
