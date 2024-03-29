### General Notes

Is a technique to verify the **integrity** and **authenticity** of a message.
* An authenticator sent with message is used.

This authenticator can be:
* [[Digital Signatures]].
* Hash functions.
* Message Authentication Codes. (MAC)
	* HMAC
	* CMAC

> [[Encryption]] is also a form authentication.

---
### Message Authentication Codes (MAC)

An extra piece of information that is attached to a message.
- It is created using the data of the message, and some shared secret key.
- It is regarded as a cryptographic checksum.
- The generation of the MAC is a many to one function, meaning multiple messages can have the same MAC.
- The output MACs are usually of the same size.

Nevertheless:
1. It should be infeasible to find two messages with the same MAC.
2. MACs should be uniformly distributed, such that no patterns exist to allow attackers to generate their own MACs.
3. MACs should depend on all bits of the message to reduce the possibility of a [[Cryptanalysis]] attack.

#### Operation
Once a message is received, the recipient calculates a MAC for this message using the same shared secret key.
1. This MAC is compared to the sent MAC.
2. If they are the same, then the message is ok.
3. Otherwise, this message has been tampered with.

> If the MAC is secure, the attacker should be unable to create valid MACs for messages that they have never seen before.
#### Security Features
These MACs provide **authenticity** since they can only be calculated by the owners of the shared secret key.

> MACs also provide **integrity** in the sense that these MACs cannot themselves be forged since the keys used to create them are only known by the communicating parties, hence, the message cannot be tampered with and go unnoticed. 

What is missing, is **confidentiality**. This can only be guaranteed if the message and its MAC are encrypted before being sent.
- The MAC can be computed either after encryption, or before it.
- It is a better standard to compute MAC before encryption.

---
### Hash Functions

Hash functions are similar to MACs, but these functions are known publicly, without the use of a key.
* They are used to detect changes to a message, hence offering **integrity**.
* They are also used to create [[Digital Signatures]].

> The output of a hash function is of a constant size regardless of input size, meaning that there is a possibility of collision.

However, it is infeasible to find two messages that have the same hash. It is also infeasible to find the original message given the hash, since it is a **one-way** function.

---
### Keyed-Hash MAC (HMAC)

This technique combines hash functions and MACs. 
* Using a hash function that takes as input the message and a secret key to generate a MAC; the HMAC.
* The message is the result of the concatenation with some fixed strings, the `ipad` and `opad`.

> The hash therefore depends on the key and the message.

The security of the HMAC therefore depends on the security of the hash function used.

---
### Encryption in Message Authentication

All of these encryption techniques ensure **integrity**, as the creation of the MAC and its usage provides this security feature.

**Authenticated Encryption** schemes manage to provide **confidentiality**, **integrity**, and **authenticity**.

> The encryption and MAC functions should use different keys, because using the same key in an authenticated encryption scheme makes the scheme vulnerable to a large category of potential attacks.

##### Symmetric Encryption

There is authenticity as only the holders of the shared symmetric key can create messages.
* **Authenticity** is achieved given that the key is only known to the two communicating parties.

Using checksums and error detection mechanisms can also be implemented to ensure the **integrity** of the message.

##### Asymmetric Encryption

**Authenticity** cannot be guaranteed because anyone can create messages given the publicly known public key. However:
* Can guarantee authenticity through [[Digital Signatures]] and [[Certificates]], where message senders can sign the message using their private keys, and then encrypt the entire message using the recipient's public key.

This ensures that the receiver, and only the receiver, can access the message. Not only does this ensure **authenticity**, but it also provides **confidentiality**.

##### Cipher-Based MAC (CMAC)

Similar to HMAC, but instead of a hash function, it works using a cipher function, such as the ones provided in [[Symmetric Ciphers]].

> The encryption is dependent on two subkeys that are generated from the main shared secret key.

It is a block cipher technique, and it encrypts each block of the message `xor`ed with the encryption of the previous block.
* If the blocks are not integer multiples of the message, then padding is used.

1. If there is no padding to be used, then only one key is to be used throughout the process.
2. If there is padding to be used, then the second key will be used at the last step of the encryption process.

This process is collision resistant unlike the hash based MAC.
##### Counter with CBC Mode

It is an authenticated encryption algorithm designed to provide both authentication and confidentiality. 
* CCM combines the counter mode (CTR) for encryption and the Cipher Block Chaining Message Authentication Code (CBC-MAC) for authentication.

First, the **authentication** tag is generated.
1. A nonce, the headers and associated data, and the plaintext, are input to a cipher function.
2. This cipher function is the CBC mode, and it is used to generate the tag.

Second, is the encryption step to ensure **confidentiality**.
1. The plaintext is input to the CTR mode, which is used to generate the ciphertext.
2. The CTR mode is also used to to encrypt the tag and produce the ciphertext.
3. The two ciphertexts are then concatenated together to form the message.

> This mode uses a nonce, hence, it must never be used again.

This technique is also very complex, as it requires the data pass through two processes. Moreover, to verify the message tag, it must first be decrypted.

> **Integrity** is maintained since any change to any part of the message will result in a mismatch at the recipient due to its usage of CBC, where dependency on each previous block will reveal any minor changes.

---
