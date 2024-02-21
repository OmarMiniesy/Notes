
### General Notes

This is a technique through which cryptographic algorithms used for [[Encryption]] are broken.

> Another technique is through brute force, but this is very computationally expensive and takes a long time.

**Confusion** and **Diffusion** are used to counter cryptanalysis attacks:
* **Confusion**: Obscure the relationship between the key and the ciphertext. Done through *substitution* operations.
* **Diffusion**: Dissipate the statistical structure of the plaintext into the ciphertext, making it harder to perform statistical attacks. Done through *permutation* operations.

> An [[Encryption]] scheme is secure if the attacker cannot learn anything about the plaintext if not previously known.

---
### Objectives

- **Decrypting Messages**: The primary objective is to decrypt messages without having access to the key that was used for encryption.
- **Finding the Key**: In some cases, cryptanalysts aim to recover the secret key itself. This allows them to decrypt all messages that were encrypted with that key.
- **Identifying Weaknesses**: By finding vulnerabilities in cryptographic algorithms or implementations, cryptanalysts can help in strengthening those systems against attacks.
- **Forgery**: Creating a message that appears to be encrypted by a specific key or mimicking the signature in digital signature schemes.

---

### Indistinguishability

It pertains to the inability of an attacker to distinguish between ciphertexts that encrypt different messages, even if the attacker is allowed to choose the messages to be encrypted.

> There are two types of indistinguishability.

##### 1. IND-CPA

This stands for *Indistinguishability under Chosen Plaintext Attack*. 

* A security standard for encryption schemes, a basic requirement for encryption schemes.
* Security against attackers that can choose plaintexts to encrypt and obtain their ciphertexts.
* The attacker cannot gain any useful information from ciphertexts even though the plaintexts are known.

Achieved using [[Encryption#Non-Deterministic Encryption]], where randomness is introduced in the encryption process.
##### 2. IND-CCA

This stands for *indistinguishability under Chosen Ciphertext Attack*.

* A security standard that is stronger than **IND-CPA**.
* Security against attackers that can choose ciphertexts and obtain their corresponding decrypted plaintext.
* The attacker cannot gain useful information from decrypted plaintexts even though the ciphertext is known.

Achieved using additional cryptographic mechanisms such as message authentication codes or digital signatures.

1. **IND-CCA1**: The attacker must make all decryption queries before receiving the challenge ciphertext. After the challenge is received, the attacker cannot request the decryption of any more ciphertexts
2. **IND-CCA2**: Allowing the attacker to continue making decryption queries even after receiving the challenge ciphertext. The attacker can adapt their strategy based on the information gained from previous decryption queries.

---
### Attacks

These are the types of cryptanalysis attacks that can be executed based on amount and type of information available to the attacker.

###### Ciphertext Only

* Knows only the ciphertext and the [[Encryption]] algorithm used.
* This attack relies on statistical analysis, pattern recognition, and assuming that the plaintext is in a readable/understandable format. 

Example: Used to break most of the [[Substitutional Ciphers]].

###### Known Plaintext

- Knows the ciphertext and the plaintext.
- The goal is deduce the key by analyzing how encryption process works through weakness discovery.

Example: Cryptanalysis of historical ciphers where intercepted messages have been partially decrypted or where standard messages (known formats or greetings) have been identified.

###### Chosen Plaintext

* Choose arbitrary plaintexts to be encrypted and then analyze the resulting ciphertexts
* Powerful since attacker can obtain information through playing with the plaintext and seeing how the ciphertext results.

Example: Differential cryptanalysis, where the attacker chooses plaintexts that differ in specific ways to observe how differences affect the ciphertext, potentially revealing information about the encryption algorithm or key.

###### Chosen Ciphertext

* Choose ciphertexts and obtain their corresponding plaintexts.
* This process can be used to obtain the private key or to find weaknesses.

Example: Adaptive chosen-ciphertext attacks on public-key cryptosystems, where the attacker exploits properties of the decryption algorithm to eventually uncover the private key.

###### Related-key Attack

* Observes the operation of the encryption algorithm under several different keys.
* The keys are known to have a specific mathematical relationship to each other.
* Used to deduce the secret key or to find weaknesses.

Example: Attacks on block ciphers where slight variations in the key lead to predictable or exploitable outcomes in the ciphertext.

---

