# Challenge

* **Points**: 53
* **Solves**: 59
* **Files**: [ainissesthai.py](./ainissesthai.py)

```
A team of codebreakers had to invent computers to break this cipher. Can you figure out what the flag is?
Remote: nc ainissesthai.chal.perfect.blue 1
Note: enter flag as pbctf{UPPERCASEPLAINTEXT}
By: UnblvR
```

# Solution
The server is encrypting the flag 50 times with different values using Enigma, which has a property that no letter ever encrypts to itself. We can recover the flag by getting many ciphertexts and eliminate characters until we're left with one.

```python
from pwn import *
from string import ascii_uppercase

flag = [set(ascii_uppercase.encode()) for _ in range(17)]
while any(len(c) != 1 for c in flag):
    r = remote('ainissesthai.chal.perfect.blue', 1)
    cts = r.recvall().split()
    for ct in cts:
        for i, c in enumerate(ct):
            if c in flag[i]:
                flag[i].remove(c)

flag = bytes(int(c.pop()) for c in flag).decode()
print(f'pbctf{{{flag}}}')
```

# FLAG
`pbctf{FATALFLAWINENIGMA}`
