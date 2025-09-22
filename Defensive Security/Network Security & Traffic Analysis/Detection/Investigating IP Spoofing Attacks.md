### General Notes

The [[IP]] address can be easily spoofed or changed in packets to trick other [[Protocol]]s or bypass certain security controls.
- Can also be used to perform [[Denial of Service (DOS)]] attacks.

Can also lead to *LAND* and *SMURF* attacks:
- **Land**: This is when the source address matches the destination address causing confusion and denial of service.
- **Smurf**: This is when packets are spoofed to send [[ICMP]] packets from a victim host. The replies are then all sent to the victim source host causing resource exhaustion.

---
