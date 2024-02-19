### Important Terms

1. Types of data:
	* **Plaintext**: the text that the senders want to encrypt, and the reciever to obtain after decryption.
	* **Ciphertext**: the text that is output from the encryption process.

2. Security features:
	- **Integrity**: the assurance that data has not been altered in an unauthorized manner from its original state.
	- **Confidentiality**: ensures that information is accessible only to those authorized to have access
	- **Authentication**: the process of verifying the identity of a user, system, or entity.
	- **Non-repudiation**: provides proof of the origin and integrity of data in a way that cannot be denied by the sender. It ensures that a sender cannot falsely deny sending a message or performing an action, and a receiver cannot deny receipt.

3. Schemes are: 
	* **Unconditionally secure**: ciphertext generated does not contain enough information to determine the plaintext.
	* **Computationally secure**: Cost of breaking the ciphertext is more than the value of the information itself, or the time of breaking the ciphertext exceeds the useful lifetime of the information.

---
### Symmetric Encryption

There is one key, called a **private key**.
* This is a shared key between sender and reciever.

The key is used at the sending side to encrypt the plaintext, and the same key at the reciever is used to decrypt the ciphertext.

> Very efficient and fast since it is less computationally expensive.

###### Types of Symmetric Ciphers

The processes of encryption and decyption can take place using two techniques:
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
* The private key is used to encrypt the plaintext to ciphertext
* The public key is used to decrypt the ciphertext to plaintext. This key should be shared in a secure manner.

The sender uses the recipient public key to encrypt the plaintext. Only the recipient with the mathematically related private key can encrypt the ciphertext.

> The private key is a secret, and should not be easily derived from the public key.

##### Security Standards

1. Achieves **Integrity** because the digital signature of the public/private key used to perform an operation can be verified.
2. Achieves **confidentiality** because data is encrypted using the recipient's public key, so only the recipient that has the private key can decrypt.
3. Achieves **authentication** by using certificates.
4. Achieves **non-repudation** for the same reason as integrity, the digital signature created by using the respective private/public key for the user.

---

