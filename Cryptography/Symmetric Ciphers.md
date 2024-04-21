
### General Notes

Symmetric ciphers are a type of cryptographic technique that operates using one shared secret key.

There are two main types of symmetric ciphers; either **block** or **stream**.
* **Block ciphers**: These encrypt data in fixed-size blocks, typically 64 or 128 bits at a time.
	* These ciphers are *deterministic*. The same plaintext and key will always produce the same ciphertext.
* **Stream ciphers**: These encrypt plaintext messages one bit or one byte at a time.

> There are various modes that utilize both of these types.

---

### Electronic Codebook Mode (ECB)

The plaintext is broken down into independent blocks, and each block is encrypted to its respective ciphertext block.
* This uses the **Block ciphers** technique.

> Useful for secure transmission of single values, or few blocks of data.

##### Decryption

The process is reversed, where each ciphertext block is decrypted into its respective plaintext block using the key.

##### Characteristics

* **Simplicity**
* **Parallel processing**: allows parallelization since each block of plaintext is encrypted independent of the others, and the same with decryption.
* **Error propagation**: there is no error propagation as each block is independently processed.

##### Limitations

* **Pattern Obfuscation**: patterns aren't sufficiently obfuscated which is vulnerable to [[Cryptanalysis]] attacks. This is the case with data that have lots of repetitions.
* **Deterministic**: The same block of plaintext always gets encoded into the same block of ciphertext when the same key is used, there is no randomization.
* Not **IND-CPA** secure.

> Shouldn't be used with data that have lots of patterns, or repeated content.

---

### Cipher Block Chaining (CBC)

The plaintext is broken down into blocks, and each block of plaintext is `xor`ed with the previous ciphertext block before it is encrypted.
* Uses the **block cipher** technique.
* The first block is `xor`ed with an **initialization vector (IV)** which is a random value that is as long as the block size.

> The initialization vector is a random value that should be unique and unpredictable, a secret like the key.

> Useful for bulk transmission of data.

##### Decryption

The process is reversed, where each block of ciphertext is decrypted and the result of that decryption is `xor`ed with the previous ciphertext.
* For the first block, it is `xor`ed with the **initialization vector (IV)**.

##### Characteristics

- **Pattern Obfuscation**: can obscure patterns because of the `xor` operation with the previous block, and this changes every time using a different IV.
- **Dependency Chain**: There is a dependency chain between the blocks of data.
- **Parallelization**: There is parallelization in the decryption process, but not for the encryption process.

##### Limitations

- **Error Propagation**: if there is an error in one block, all the other blocks are also affected.
- **Initial Vector (IV) Sensitive**: The IV must be unique and unpredictable.

> **IND-CPA** secure for unpredictable **IV**.

---

### Cipher Feedback Mode (CFB)

This is another **stream cipher** technique but it functions similar to that of **block cipher**. It encrypts data in segments smaller than the block size, which is useful for data streams of size not divisible by the block size.
* It takes an **Initialization Vector (IV)** for the first block and encrypts that, it should be unique and unpredictable. 
* The encryption of the block or the IV in the first case is then `xor`ed with the plaintext that is available (not fixed size). This produces the ciphertext.

> Useful for stream data encryption.
##### Decryption

Mirrors the encryption technique. The ciphertext from previous block or IV is encrypted and then its output is `xor`ed with the ciphertext to produces the plaintext.

##### Characteristics

* **Flexibility**: Can handle variable sizes of data, since it is **stream cipher**.
* **Parallelization**: Decryption process is parallelizable but encryption is not.

##### Limitations

* **Error propagation**: errors propagate throughout the process for a few blocks, not until the end.
* **Stalling**: must stall after encrypting the number of bits that have arrived and wait for the next ones to arrive.

> It is **IND-CPA** secure for a random **IV**.

---

### Output Feedback Mode (OFB)

**Stream cipher** technique that encrypts only the **Nonce** and the key together. This output is then chained to the other encryption blocks, this is the feedback.
* The corresponding ciphertext for a group of bits is the result of the `xor` of the output of the encryption and the ciphertext.
* Decryption is simply the mirror image of this operation, where the ciphertext is `xor`ed to get the plaintext.

> The feedback operation of the blocks is independent of the message itself, it relies on the nonce and the key.  Hence, the encryption process can be calculated beforehand.

> Useful for stream encryption on noisy channels.
##### Characteristics

* **Error Propagation**: There is no error propagation here as the message itself is not used in the chain process.
* **Parallelization**: The encryption and decryption processes are parallelizable.

##### Limitations

- **Synchronization**: The sender and receiver must remain in sync.
- **Secrets**: Since only the key and nonce are used to generate the encryption, they must be unique and unpredictable, and never reused.

> This is **IND-CPA** secure due to the uniqueness and randomness of the nonce.

---

### Counter Mode (CTR)

Similar to the **output feedback mode**, but instead of the feedback being the encryption of a nonce, it is a counter. This is a **block cipher** technique.
* This means there must be a different counter and key used for every plaintext block that is transmitted.

> Useful for high speed network encryptions.

Its characteristics and limitations match the **OFB** mode.

---
