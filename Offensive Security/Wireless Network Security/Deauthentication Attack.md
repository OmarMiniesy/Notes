### General Notes

This is a [[Data Link Layer]] attack where an attacker fabricates a *deauthentication frame* and sends it to the client.
- The attacker modifies the sender MAC address of the frame  and pretends that it originates from the [[Device Types#Access Point (AP)|Access Point]]
- This causes the client to disconnect from the network.

If the client disconnects, a reconnection attempt is done again. The attacker can now:
-  Capture the [[Wi-Fi Connection|WPA]] handshake and perform a dictionary attack.
- Enforce users to disconnect from the legitimate network and connect to their false network.

---
### Attack

This is done by `aireplay-ng` and `mdk4`.
- They specify a *reason code* of `7` for deauthentication.

---
