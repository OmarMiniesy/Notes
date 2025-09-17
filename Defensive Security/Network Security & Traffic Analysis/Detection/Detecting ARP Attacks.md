### General Notes

The [[Address Resolution Protocol (ARP)]] protocol is used to allow devices to identify themselves on the network.
- The [[Arp Poisoning]] attack allows attackers to act as other devices on the network or become a *Man in the Middle*.

---
### Using [[Wireshark]]

###### Detecting ARP Spoofing

A suspicious situation occurs when two ARP responses (`opcode=2`) are for the same [[IP]] address and provide a different [[Data Link Layer#MAC Address|MAC Address]].
- The challenge is to know which MAC address is legitimate and which one is suspicious.

###### Detecting ARP Flooding

When a single device sends a huge load of ARP requests with different destination IP addresses


> If TCP connections are consistently dropping, it's an indication that the attacker is not forwarding traffic between the victim and the router if the attacker formed a MITM.

###### Nice Wireshark Display Filters

| **Notes**                                                                                                                                                                                | **Wireshark filter**                                                                                                                                                                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Global search                                                                                                                                                                            | - `arp`                                                                                                                                                                                                                                |
| To search for a MAC address                                                                                                                                                              | - `eth.addr == 00:00:00:00:00:00`<br>- `eth.src`, `eth.dst`.                                                                                                                                                                           |
| - Opcode 1: ARP requests.<br>- Opcode 2: ARP responses.<br>- **Hunt:** Arp scanning<br>- **Hunt:** Possible ARP poisoning detection<br>- **Hunt:** Possible ARP flooding from detection: | - `arp.opcode == 1`<br>- `arp.opcode == 2`<br>- `arp.dst.hw_mac==00:00:00:00:00:00`<br>- `arp.duplicate-address-detected or arp.duplicate-address-frame`<br>- `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)` |
