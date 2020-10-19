## n1vault

There was a secret logic that triggered when SIGFPE is sent to the program. The main goal of the challenge is to trigger this secret logic.

There's only one point that SIGFPE signal can be triggered, with divide-by-zero exception. 

``` c
          if ( !memcmp(&s1, &s2, 0x20uLL)
          && !memcmp(&v14, &v50, 0x20uLL)
          && 0x422048F8DF49762ELL / (v5 | v4) == 1
          && v4 == 0x9E48562A
          && v5 == 0x422048F8DF41242ELL )
```

If both `v5` and `v4` is zero, then it will be triggered.

After reversing binary, it was able to know that:

1. Every part of the input data is digested in to SHA256 and compared with the fixed value (`memcmp` above), except `data[0x10B0::2]`.
   This means we cannot change except `data[0x10B0::2]` to pass the SHA256 checking logic.
2. `v5` is the CRC64 value of the data and `v4` is the CRC32 value of the data.

So this challenge is about changing `data[0x10B0::2]` (total 12 bytes) to make both CRC32 and CRC64 to zero.

Usually, CRC has an interesting property, that $CRC(x \oplus y) = CRC(x) \oplus CRC(y)$. In this challenge, the starting value of CRCk is `(1 << k) - 1`, so this is a bit different: $CRC(x \oplus y) = CRC(x) \oplus CRC(y) \oplus CRC(0)$.

From this, for each unknown bit $x_0, x_1, ..., x_{95}$, this challenge asks: $CRC(x_0 \oplus x_1 \oplus \ldots \oplus x_{95}) = 0$. By using the property above, we can make this into $CRC(x_0) \oplus CRC(x_1) \oplus \ldots \oplus CRC(x_{95}) \oplus CRC(0) = 0$.

For $k$-th bit of CRC, we can think like: $CRC(x_0)_k \oplus CRC(x_1)_k \oplus \ldots \oplus CRC(x_{95})_k \oplus CRC(0)_k = 0$. Moreover, we can think like this way: $CRC(x_0 | x_0=1)_k \cdot x_0 \oplus CRC(x_1 | x_1=1)_k \cdot x_1 \oplus \ldots \oplus CRC(x_{95} | x_{95} = 1)_k \cdot x_{95} \oplus CRC(0)_k = 0$. We know that XOR operator is same as addition on mod 2. Therefore, this is a linear equation over mod 2 on $x_0$ to $x_{95}$.

For each bit of CRC64, we can get 64 linear equations over mod 2 on $x_0$ to $x_{95}$. For each bit of CRC32, we can get 32 linear equations over mod 2 on $x_0$ to $x_{95}$. These are total 96 equations, and unknown bits are total 96 bits. We can solve this by gauss elimination.

The solver code is here:

```python
#!/usr/bin/env sage

import struct

with open('credential.png', 'rb') as f:
    data = f.read(0x10C8)

crc32_table = []
crc64_table = []
with open('n1vault', 'rb') as f:
    f.seek(0x1960)
    for i in range(256):
        crc32_table.append(struct.unpack('<I', f.read(4))[0])
    f.seek(0x1d60)
    for i in range(256):
        crc64_table.append(struct.unpack('<Q', f.read(8))[0])

def crc64(arr):
    crc = (1 << 64) - 1
    for c in arr:
        crc = crc ^^ c
        for i in range(8):
            if crc & 1:
                crc = (crc >> 1) ^^ crc64_table[0x80]
            else:
                crc = crc >> 1
    return crc ^^ ((1 << 64) - 1)

def crc32(arr):
    crc = (1 << 32) - 1
    for c in arr:
        crc = crc ^^ c
        for i in range(8):
            if crc & 1:
                crc = (crc >> 1) ^^ crc32_table[0x80]
            else:
                crc = crc >> 1
    return crc ^^ ((1 << 32) - 1)

mat = [ [0 for j in range(96)] for i in range(96)]
for i in range(12):
    tmp = bytearray([0 for _ in range(0x10C8)])
    for j in range(8):
        tmp[0x10B0 + 2 * i] = 1 << j
        v32 = crc32(tmp)
        v64 = crc64(tmp)

        for k in range(32):
            bit = (v32 >> k) & 1
            mat[k][i * 8 + j] = bit
        for k in range(64):
            bit = (v64 >> k) & 1
            mat[k + 32][i * 8 + j] = bit

target = [ 0 for i in range(96) ]
v32 = crc32(data) ^^ crc32([0 for _ in range(0x10C8)])
v64 = crc64(data) ^^ crc64([0 for _ in range(0x10C8)])

for i in range(32):
    bit = (v32 >> i) & 1
    target[i] = bit
for i in range(64):
    bit = (v64 >> i) & 1
    target[i + 32] = bit

mat = Matrix(GF(2), mat)

ans = mat.solve_right(Matrix(GF(2), target).transpose())

tmp = bytearray(data)

for i in range(12):
    for j in range(8):
        val = int(ans[8 * i + j][0])
        tmp[0x10B0 + 2 * i] = tmp[0x10B0 + 2 * i] ^^ (val << j)

with open('credential_false.png', 'wb') as f:
    f.write(tmp)
```

The flag was `n1ctf{fa4bdf1d540831c88ca40794fc128f10}`.