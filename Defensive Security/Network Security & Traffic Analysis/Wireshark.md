### General Notes

A network sniffer tool and [[Protocol]] analyzer like [[Tcpdump]] but with a graphical interface.
- *Sniffing* is seeing the data transmitted over a network.
- Wireshark gives analysis capabilities on the captured data.

Capture all traffic seen by Network Interface Card (NIC).
- Network Interface Cards (NIC) can be in either *promiscuous mode* or *monitor mode*.
- *Promiscuous mode* NIC receive all network traffic regardless of the destination of the traffic. 
- *Monitor mode* allows NICs to listen to all wireless traffic in the vicinity, regardless of the traffic destination.

Features given by Wireshark:
- Deep packet inspection.
- Supports a lot of [[Protocol]] types.
- Has decryption capabilities for encrypted protocols ([[Encryption]]).

> There is a terminal version for Wireshark - `Tshark`, and text based user interface version called `Termshark`.

---
### Processing and Filtering

There is filtering and processing capabilities present in Wireshark both before and after the capture.
- Before the capture, they are called *capture filters*. These are in the Berkley Packet Filter syntax and it drops any packet that doesn't match the filter. Good to trim down data.
- During or after the capture, they are called *display filters*. Used to filter the packets to get the exact packets and traffic needed. List of all [Filters](https://www.wireshark.org/docs/dfref/).

> Information that is displayed within square brackets is calculated by Wireshark, it is not information that can be obtained directly from the packet.

---
### Wireshark Plugins

Wireshark has many plugins or extra tools that give us advanced analysis and monitoring capabilities.
- Part of the tabs at the top are the *Analyze* and *Statistics* tabs which give great insights into the data and packets being examined.

For the *Statistics* tab, there are:
- **Protocol Hierarchy**: Shows the protocols that were used in the hierarchy of the network stack, and shows the percentage and number of packets that were being used in each protocol.
- **Conversations**: Shows all the conversations between the end devices for the different protocols. Give information about the addresses, the number of packets, their sizes, the packet directions, the bit speed, and the duration of the conversations.
- **Endpoints**: Shows information for all packets per endpoint per protocol.

For the *Analyze* tab, [[Transport Layer#TCP|TCP]] streams can be followed, conversation types can be filtered on, and packet filters can be added.

*Follow TCP Stream* is a feature that allows stitching together the TCP packets of a conversation in a readable format between the two communicating devices.
- Is usable on any protocol that uses the TCP transport layer protocol.
- Allows for data such as images and files to be pulled out of the capture.
- To use, right click on a packet from the conversation stream, then choose *follow*, then choose *TCP*.
- Can also be used through the display filter `tcp.stream eq #`, where the `#` is the TCP conversation we wish to follow.

To extract data and files from a capture:
1. Stop the capture.
2. Choose the `file` tab.
3. Choose `export`.
4. Choose the protocol to extract from.

> The `Expert Information` under the `analyze` tab shows remarks of several types, like errors, warnings, notes, chats, and comments.

---
### Decrypting Traffic

If the key used for encryption is obtained for [[Protocol]]s like [[HTTPS]] or Remote Desktop (RDP), it can be placed in Wireshark to decrypt the traffic for easier analysis..
- Head to *Edit*, then *Preferences*, then *Protocols*, then *TLS*.
- We can then choose *Edit* next to *RSA Keys list*. and fill in the needed data for the [[IP]] address of the server, the [[Port]] used, the protocol, and the key file itself.
- Saving and refreshing the `pcap` file will allow us to investigate in clear-text.

---
### Investigating [[File Transfer Protocol (FTP)]]

To save files that were transported over `ftp`:
1. Identify any FTP traffic using the `ftp` display filter.
2. Look at the command controls sent between the server and hosts to determine if anything was transferred and who did so with the `ftp.request.command` filter.
3. Choose a file, then filter for `ftp-data`. Select a packet that corresponds with our file of interest and follow the TCP stream that correlates to it.
4. Once done, Change "Show and save data as" to "Raw" and save the content as the original file name.
5. Validate the extraction by checking the file type.

---
