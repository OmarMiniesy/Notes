### General Notes

Takes advantage of the way devices nowadays automatically connect to wireless networks they remember that they connected to before.

Abuses the **probe request packet**, which is a packet sent by clients to connect to a an Access Point [[Device Types]].

---
### Methodology

1. **Automatic Connection Feature**:
    - Many mobile devices are designed to simplify user connectivity by automatically connecting to familiar Wi-Fi networks. These devices broadcast **probe request** that may include the names (SSIDs [[Identifiers]]) of previously connected networks.
2. **Listening for Probe Requests**:
    - In a Karma attack, the attacker's device listens for these probe requests seeking known networks.
3. **Spoofing a Trusted Network**:
    - Upon capturing a probe request, the attacker configures their malicious Wi-Fi access point to impersonate one of these trusted network names. Because the device recognizes the SSID as familiar, it may connect to the attacker's network automatically without user interaction.
4. **Man-in-the-Middle (MitM) Position**:
    - Once a device connects to a malicious network, the attacker can perform a Man-in-the-Middle (MitM) attack. This position allows the attacker to intercept, read, and potentially alter the data sent between the victim's device and the internet. The attacker can also attempt to inject malware or exploit other vulnerabilities in the device's communications.

---