### General Notes

> Cryptographic network [[Protocol]] for operating network services.
> Operatoes on [[Port]] 22.

---
### Connecting to SSH

> Connecting via terminal to a given [[IP]] address.
```
ssh <username>@<ip-address>
```

### id_rsa private key

> If the file `id_rsa` is found, this is a private key that can be used to connect to SSH.
```
ssh -i id_rsa <username>@<ip-address>
```

> If it is encrypted, follow the steps in [[John the Ripper#ssh2john]].
> It is encrypted if when reading the contents of the file we see in its header `proc-type: 4, encrypted`.

> The `id_rsa` must have read only permissions.
```
chmod 600 id_rsa
```

---

