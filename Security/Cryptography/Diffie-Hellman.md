### General Notes

An algorithm developed to publicly share secret keys between communicating nodes to establish a common key.
* Used in Asymmetric [[Encryption]].
* This shared key is a session key, and is a valid for a single communicating session. Once the session expires, a new key is needed.

> The value of the established common key depends on private and public key information of the participants.

The computations themselves to obtain the key are easy, but it is computationally secure, making it difficult to attack.

---

### How the Algorithm Works

Assume there are two communicating parties, Alice and Bob.

1. **Initialization**:
    - Both parties agree on a large prime number $p$ and a base $g$, where $g$ is a primitive root modulo $p$. These numbers are not secret and can be known by everyone.
2. **Private Keys**:
    - Each party selects a private key at random. Let's call the private keys $a$ and $b$ for Alice and Bob, respectively. These keys are kept secret and are not shared.
3. **Public Keys**:
    - Alice computes her public key by calculating $g^a\mod(p)= A$ and sends this value to Bob.
    - Similarly, Bob computes his public key by calculating $g^b\mod(p) = B$ and sends this value to Alice.
4. **Shared Secret**:
    - Upon receiving Bob's public key, Alice computes the shared secret by raising Bob's public key to the power of her private key and taking the modulo $p$ :  $B^a\mod(p)$.
    - Similarly, Bob computes the shared secret by raising Alice's public key to the power of his private key and taking the modulo $p$ : $A^{b}\mod(p)$.
5. **Communication**:
    - Now that Alice and Bob have a shared secret, they can use this key to encrypt and decrypt messages between them securely.

---

### Security of Diffie-Hellman

It is vulnerable to a Man In the Middle (MITM) attack if no [[Digital Signatures]] are used to verify the authenticity and integrity of the messages.

###### Proof of Concept

- In the midst of this exchange, an attacker, Eve, intercepts Alice's public value $A$ and sends her own public value $E$ to Bob.
- Similarly, Eve intercepts Bob's public value $B$ and sends $E$ to Alice.
- Now, Alice believes $E$ is Bob's public value and calculates the shared secret $s = E^a \mod p$, while Bob believes $E$ is Alice's public value and calculates $s = E^b \mod p$.
- However, because Eve has generated $E$, she can calculate the shared secrets established between her and Bob and her and Alice separately.
- As a result, Eve can decrypt any messages encrypted with these shared secrets, alter them if she wishes, and then re-encrypt them with the appropriate key before sending them on to the intended recipient.

---
