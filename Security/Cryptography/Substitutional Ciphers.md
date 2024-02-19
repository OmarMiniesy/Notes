
### General Notes

When plaintext characters are substituted by others.
* Numbers
* Symbols
* Letters

> This can also be applied to sequences of bits.

The output of a cipher operation is called **ciphertext**, and its input is called the **plaintext**.

---

### Caeser Cipher

Replace each letter by the third letter down in the alphabet.
* This produces a transformation done through shifting.

> The algorithm itself when used was 3 only, can be any number.

Given $k$ is the shifting amount and $p$ is the current letter, the cipher text of each character is:

$$ c = (p+k)mod(26) $$

> The `mod(26)` ensures that it is a circular process over the entire alphabet.

##### Breaking the Cipher

Using a brute force attack to try all shifts until a recognizable plain text is produced.

---

### Monoalphabetic Cipher

Mapping each plain text letter to a different randomized cipher text letter.
* The key is responsible for holding this mapping.

> Key length is $26!$
* Very long key length which isnt desired because it increases computational overhead.

##### Breaking the Cipher - [[Cryptanalysis]]

Letters used in the english vocab are not commonly used, and their usage can be divided into a propabilistic distribution.

> Map the probability distribution of the letters in the cipher text to the probability distribution of letters in the english language.
* This also works for double and triple letters, not just singular characters.

---

### Playfair Cipher

Uses a 5x5 matrix that is based on a keyword which doesn't have repeated characters.
* Fill in the matrix first with that keyword.
* Then fill up the matrix with the remaining letters of the alphabet.
* Encrpytion takes places on two letters a time, for each pair in the plain text.

Requirements for plain text before encryption:
1. If there is odd number of letters, add a filler character in the end.
2. If there is a pair of repeated letters, add a filler character in between them.

##### Encryption

* If both letters are in the same row, replace them with the letters immediately to the right.
* If both letters are in the same column, replace them with the letters immediately below them.
* If the letters form a rectangular grid, each letter is replaced by the letter on the same row but opposite corner of the rectangle.

##### Decryption

* For letters in the same row, each letter is replaced by the letter immediately to its left.
- For letters in the same column, each letter is replaced by the letter immediately above it.
- For letters forming a rectangle, each letter is replaced by the letter on the same row but at the opposite corner of the rectangle, just like in encryption.

##### Breaking the Cipher - [[Cryptanalysis]]

There are 676 possible digrams, $26^2$.
* Therefore, we need a frequency table for 676 entries to analyze the cipher text.
* Can be broken using frequency analysis like the monoalphabetic cipher using that table.

---

### Vigenere Cipher

Uses multiple cipher alphabets, where a key is used to map which alphabet is used for each letter of the plain text.
* Makes it stronger against frequency analysis attacks using probability distrubtion of text.
* Type of polyalphabetic cipher.

> The key is a word, where each letter specifies which alphabet to use. This key is repeated on all the plain text.

##### Breaking the Cipher - [[Cryptanalysis]]

Find repetitions to determine key size, and hence, the number of alphabets used.
* Then use the probability distribution attack like the monoalphabetic cipher.

---

