### General Notes

A method for Asymmetric, public key, [[Encryption]].

> Each user generates a public and private key pair.

---
### Key Generation:

1. **Choose two distinct large random prime numbers**, typically denoted as $p$ and $q$.
2. **Compute** $n = pq$: $n$ is used as the modulus for both the public and private keys. Its length, usually expressed in bits, is the key length.
3. **Compute $\phi(n) = (p-1)(q-1)$**: This value is used in calculating the public and private keys.
4. **Choose an integer $e$ such that $1 < e < \phi(n)$ and $e$ is co-prime to $\phi(n)$**: $e$ becomes the public exponent and is typically chosen to be a small value such as 65537 for efficiency reasons.
5. **Compute $d$** to satisfy the congruence relation $d \times e \equiv 1 \pmod{\phi(n)}$: $d$ is the private exponent. $d$ can be computed efficiently using the Extended Euclidean algorithm.

After these steps, the public key consists of the pair $(n, e)$ and the private key consists of $(n, d)$.

### Encryption:

- To encrypt a message $m$, where $0 \leq m < n$, compute the ciphertext $c$ as: $c =m^{e}\mod(n)$
### Decryption:

- To decrypt a ciphertext $c$, compute the original message $m$ as: $m=c^{d}\mod(n)$

---