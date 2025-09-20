### General Notes

An attack conducted on wireless networks where an attacker mimics the properties of an Access Point. ([[Device Types]])
- This is done by copying the [[Data Link Layer#MAC Address]] and its [[Identifiers]] - SSID.

This fake Access Point misleads users into connecting to it which exposes sensitive data.
- Can also act as a Man in the Middle between the user and the internet.

To detect evil access points, we can use `Airodump-ng`:
```bash
sudo airodump-ng -c 4 --essid <ESSID> <INTERFACE> -w raw
```
- The `-c` is the channel of the [[Device Types#Access Point (AP)|Access Point]].
- The `-essid` is the [[Identifiers#Extended Service Set Identifier (ESSID)|ESSID]], or name of the wireless network.
- The `-w` is the output file.

---
### How the Evil Twin Attack Works

1. **Setup**: The attacker surveys the area to identify a popular Wi-Fi network. This could be in a coffee shop, a library, an airport, or a corporate environment. The attacker then sets up a rogue access point with the same SSID and similar security settings as the legitimate network. Advanced attackers may also spoof the MAC address of the router providing the legitimate network to make their rogue access point seem even more convincing.
2. **Broadcast**: The malicious access point is configured to broadcast a strong signal to entice devices into connecting to it instead of the legitimate one. Users looking to connect see this network as just another legitimate network option, often indistinguishable from the real one.
3. **Connection**: When users connect to the "Evil Twin" access point—thinking they are connecting to a legitimate network—they are actually connecting to the rogue setup by the attacker. All their data traffic goes through this access point.
4. **Interception**: With the data flowing through their network, the attacker can use various techniques to intercept and capture any unencrypted communications. This includes emails, passwords, credit card numbers, and other personal data. Additionally, if the connection requires a login page, the attacker can create a phishing page to capture users' credentials directly.
5. **Manipulation**: Besides stealing data, attackers can also manipulate the data or inject malware into the websites being visited by the user, further compromising the user’s device and security.

---
