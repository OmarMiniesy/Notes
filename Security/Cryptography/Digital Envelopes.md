
### General Notes

A technique for securing messages that combines both [[Encryption]] types, the symmetric and asymmetric.
* Provides **confidentiality** of the data being sent.

The process of using a digital envelope involves two main steps: encrypting the data with a symmetric key (also known as a session key) and then encrypting that symmetric key with the recipient's public key.

---

### Creation of a Digital Envelope

1. **Encrypting the Message**:
    - The sender generates a random symmetric key (also known as a session key) specifically for this message.
    - The message is encrypted using this symmetric key with a symmetric encryption algorithm (e.g., AES). Symmetric encryption is fast and efficient for encrypting large amounts of data.
2. **Encrypting the Symmetric Key**:
    - The sender then encrypts the symmetric key itself with the recipient's public key using an asymmetric encryption algorithm (e.g., RSA).
    - This step ensures that only the recipient, who possesses the corresponding private key, can decrypt the symmetric key.
3. **Sending the Digital Envelope**:
    - The sender transmits both the encrypted message (the ciphertext) and the encrypted symmetric key to the recipient.
    - These two components together form the "digital envelope." The envelope securely contains the encrypted message and the means to decrypt it, but only the intended recipient can open it.

### Opening a Digital Envelope

1. **Decrypting the Symmetric Key**:
    - Upon receiving the digital envelope, the recipient uses their private key to decrypt the encrypted symmetric key.
    - Since only the recipient's private key can decrypt something that was encrypted with their public key, this ensures the security of the symmetric key during transmission.
2. **Decrypting the Message**:
    - With the symmetric key now decrypted, the recipient uses it to decrypt the encrypted message.
    - The recipient can now read the original message, completing the secure communication process.

### Advantages of Digital Envelopes

- **Efficiency**: By using symmetric encryption for the message, digital envelopes can securely transmit large amounts of data more efficiently than using asymmetric encryption alone.
- **Security**: The use of asymmetric encryption for the session key ensures that only the intended recipient can decrypt the message, leveraging the security strengths of both encryption types.
- **Confidentiality**: The encrypted message and the encrypted key together ensure that the message remains confidential during transmission.

---
