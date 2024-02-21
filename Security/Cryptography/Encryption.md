### General Notes

Used to encrypt data on secure channels:
* **Link Encryption**: There is encryption on secure links between devices.
* **End to End Encryption**: Encryption between the original source and destination of the communication.

Encryption requires that there be shared secrets between the devices communicating, these are known as keys.

> The headers of the data packets should be unencrypted so that network devices can route the packets properly.

---
### Important Terms

1. Types of data:
	* **Plaintext**: the text that the senders want to encrypt, and the receiver to obtain after decryption.
	* **Ciphertext**: the text that is output from the encryption process.

2. Security features:
	- **Integrity**: the assurance that data has not been altered in an unauthorized manner from its original state.
	- **Confidentiality**: ensures that information is accessible only to those authorized to have access
	- **Authentication**: the process of verifying the identity of a user, system, or entity.
	- **Non-repudiation**: provides proof of the origin and integrity of data in a way that cannot be denied by the sender. It ensures that a sender cannot falsely deny sending a message or performing an action, and a receiver cannot deny receipt.

3. Schemes are: 
	* **Unconditionally secure**: ciphertext generated does not contain enough information to determine the plaintext.
	* **Computationally secure**: Cost of breaking the ciphertext is more than the value of the information itself, or the time of breaking the ciphertext exceeds the useful lifetime of the information.
	* **Semantically secure**: when observing the ciphertext doesn't give any information about the plaintext.

---
### Symmetric Encryption

There is one key, called a **private key**.
* This is a shared key between sender and receiver.

The key is used at the sending side to encrypt the plaintext, and the same key at the receiver is used to decrypt the ciphertext.

> Very efficient and fast since it is less computationally expensive.

###### Types of [[Symmetric Ciphers]]

The processes of encryption and decryption can take place using two techniques:
* **Stream cipher**: Works on the data bit by bit.
* **Block cipher**: Work on fixed block sizes.

###### Security Standards

1. Achieves **confidentiality** as there needs to be a key to access the data.
2. Achieves **authentication** if the key is *only known* by the two communicating parties. If the key is known to other parties, then authentication is compromised.
3. Does not achieve **integrity** as there is no guarantee that the data being sent wasn't manipulated.
4. Does not achieve **non-repudiation** since both the sender and receiver share the same key, and there is no way to prove who performed a specific action.
---
### Asymmetric Encryption

There are two keys, a **public key** and a **private key**.
* The private key is used only by the recipient, and is used to decrypt the ciphertext, as well as sign digital signatures.
* The public key which can be known by anybody, and is used to encrypt the plaintext and verify digital signatures.

Known as asymmetric because those who can encrypt cannot decrypt, and vice versa.
* The sender uses the recipient public key to encrypt the plaintext. 
* Only the recipient with the mathematically related private key can decrypt the ciphertext.

> The private key is a secret, and should not be easily derived from the public key.

##### Security Standards

1. Achieves **Integrity** because the digital signature of the public/private key used to perform an operation can be verified.
2. Achieves **confidentiality** because data is encrypted using the recipient's public key, so only the recipient that has the private key can decrypt.
3. Achieves **authentication** by using certificates.
4. Achieves **non-repudiation** for the same reason as integrity, the digital signature created by using the respective private/public key for the user.

##### Use Cases

There exists three use cases for public key cryptography:

1. Encryption and Decryption.
2. Digital Signatures to provide authentication. (public key certificates)
3. Key exchange of the session keys.

Not all algorithms achieve all of these use cases:
* The RSA algorithm does all.
* The Elliptic Curve Cryptography (ECC) does all.
* The Diffie-Hellman algorithm allows for key exchanges.
* The Digital Signal Standard (DSS) allows only for digital signatures.

---
### Non-Deterministic Encryption

An encryption scheme where encrypting plaintext with the same key produces different different ciphertexts.
* Achieved by introducing randomness.

Can be achieved using these techniques:
1. **Initialization Vector (IV)**
2. **Nonce**

---
