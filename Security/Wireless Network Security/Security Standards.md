### General Notes

There is backwards compatibility of security standards on [[Device Types]].

Important security objectives for wireless networks are:
- **Availability**: Ensuring that the wireless network is available for authorized parties.
- **Authenticity**: Establishing the trust relationships between the involved parties of wireless communication.
- **Data confidentiality**: Protecting the data against unauthorized disclosure, done through [[Encryption]].
- **Data integrity**: Ensuring that the data is accurate and not altered by any malicious actors during transmission.

---
### WEP

The first security standard for WiFi (802.11).
- Only goal was to prevent eavesdropping.

The key is augmented with an Initialization Vector [[Encryption]], and uses the RC4 stream cipher.
- There is a cyclic redundancy check (CRC-32) for integrity.

The communicating parties having the same shared key will be able to encrypt and decrypt the transmitted data.

##### Authentication

There are two techniques for authentication, **Open System Authentication** and **Shared Key Authentication**.

**Open System Authentication**: 
- Doesn't involve the sharing of a secret or a password.
- There is an authentication request sent from client to Access Point. [[Device Types]].
- An authentication response is sent from the access point that is always positive unless the access point has reached its connection limit, or the specific client is denied access.
- The only criteria is that the [[Protocol]] used by the client and the access point match.

**Shared Key Authentication**:
- There is a four step process, along with a challenge.
- The client initiates the process by sending an authentication request to the Access Point.
- The access point responds by sending a *plain-text* challenge packet to the client.
- The client receives this challenge, encrypts it using the shared WEP key, and sends it back to the access point.
- The access point, having the same key, decrypts the encrypted challenge and authenticates the client on success.

---
### WPA

An update to WEP to fix its cryptography and security issues.
- Uses TKIP (Temporal Key Integrity Protocol): adds sequence numbers to packets to protect against replay attacks.
- Adds MIC (Message Integrity Check): Better check on integrity than the CRC.

> Introduced the 4 way authentication handshake found in [[WiFi Connection]].

---
### WPA2

Also known as RSN, Robust Security Network.

> Uses AES [[Encryption]] and CCMP.

Authentication in WPA2:
* PSK, or personal mode: One shared password or shared key.
* RADIUS, or enterprise mode: Multiple passwords depending on user credentials, meaning users are verified based on credentials not a password.

---
### WPA3

Uses stronger [[Encryption]] and introduces new authentication techniques before the handshake, such as the **Simultaneous Authentication of Equals** in *private networks* and the **Opportunistic Wireless Encryption** in *public networks*.

- **SAE**: Provides better security against dictionary attacks where the attacker can compromise the network key. Uses the **Dragonfly Key Exchange** which creates a new encryption key each time a new device connects.
- **OWE**: Encryption that does not require a known password, as this is for public networks. It does not protect against MITM attacks, but it is still somewhat secure for a public network as the traffic is encrypted.

After the authentication technique chosen, the **Association** frames pass and the handshake begins. [[WiFi Connection]].

---
