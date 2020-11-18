## Happy farm

There are three levels.

## Level 1

`Fertilizer1.grow` works like:

```python
    def grow(self, seed, layer):
    	self.fertilizer = AES.new(mode=AES.MODE_CBC, key=self.key, iv=self.start_date)
        for _ in range(layer):
            seed = self.fertilizer.encrypt(seed)
        return seed
```

that `self.key` is randomly chosen, and `self.start_date` is set by the given parameter to the constructor.

What we need is the output of `Fertilizer1(my_start_date).grow(my_seed, 9000)` by using `Fertilizer1(our_date).grow(our_seed, our_layer)` twice.

As you can see, it's using AES-CBC, so we can know the value of `Fertilizer1(my_start_date).grow(my_seed, 1)` by getting `Fertilizer1(my_start_date ^ 1).grow(my_seed ^ 1 , 9000)`. After getting the value of `Fertilizer1(my_start_date).grow(my_seed, 1)`, we can calculate `Fertilizer1(my_start_date).grow(my_seed, 9000)` by `Fertilizer1(my_start_date).grow(Fertilizer1(my_start_date).grow(my_seed, 1), 8999)`.

The solver for the level 1 is here:

```python
from pwn import *
from Crypto.Util.number import *

r = remote('happy-farm.balsnctf.com', 4001)

def get_onion():
    s = ''
    for _ in range(22):
        s += r.recvuntil('\n').decode()
    s = s.replace(' ', '').replace('\n', '').replace('x', '')
    return bytearray.fromhex(s)

# Level 1
r.recvuntil('My seed:\n')
seed = get_onion()
r.recvuntil('My start date: ')
date = bytearray.fromhex(r.recv(32).decode())

seed[0] ^= 1
date[0] ^= 1
r.recvuntil('start date: ')
r.sendline(date.hex())
r.recvuntil('seed: ')
r.sendline(seed.hex())
r.recvuntil('layer: ')
r.sendline('1')

r.recvuntil('Your onion\n')
seed = get_onion()
print(seed)

date = seed[-16:]
r.recvuntil('start date: ')
r.sendline(date.hex())
r.recvuntil('seed: ')
r.sendline(seed.hex())
r.recvuntil('layer: ')
r.sendline('8999')

r.recvuntil('Your onion\n')
output = get_onion()

r.recvuntil('How would my onion looks like? ')
r.sendline(output.hex())
```

## Level 2

In this level, `Fertilizer2` uses plaintext RSA, and give a seed value:

```python
        self.e = 3
        self.seed = pow(1 << 1023, self.e, self.n)
        self.seed = long_to_bytes(self.seed)
```

`Fertilizer2.grow` looks like:

```python
    def grow(self, seed, layer):
        exp = pow(self.d, layer, self.phi)
        seed = bytes_to_long(seed)
        if seed >= self.n or seed < 0:
            raise Exception

        onion = pow(seed, exp, self.n)
        return long_to_bytes(onion)
```

We can get two values:

```python
    onion = fertilizer.grow(my_seed, layer)
    drawer.draw_onion(onion)
    # ...
    onion = fertilizer.grow(seed, layer)
    drawer.draw_eaten_onion(onion)
```

The goal is to calculate `fertilizer.grow(my_seed, 9000)`, but we cannot directly calculate it. (There are restrictions on the layer value.) Also, we don't know `n`.

First, we can calculate `n` by sending `layer = 8999`. Then it will give us `pow(1 << 1023, e * d ** 8999, n) = pow(1 << 1023, d ** 8998, n)`. From `my_seed` and `pow(1 << 1023, d ** 8998, n)`, we can calculate `n` with GCD.

```python
# Level 2
r.recvuntil('My seed is\n')
seed = get_onion()

n1 = 2 ** (1023 * 3) - bytes_to_long(seed)

r.recvuntil("layer: ")
r.sendline('8999')
r.recvuntil("your onion\n")
onion1 = get_onion()

n2 = bytes_to_long(onion1)
for _ in range(8998):
    n2 = pow(n2, 3, n1)

n = GCD(n2 - 2 ** 1023, n1)
```

Second, send `seed = pow(1 << 1023, d ** 8998, n)` and `layer = 1`, then it will calculate `pow(1 << 1023, d ** 8999, n)`, which is the value of `fertilizer.grow(my_seed, 9000)`. But LSBs are deleted in the text (`drawer.draw_eaten_onion(onion)`) so we need to use Coppersmith here to recover the deleted LSBs.

Be careful that `epslion` value of `small_roots` should be not greater than 0.0432. Total 296 bytes are unknown from 1024 bytes, so by calculating the boundary of the Coppersmith method by `1/2 * N^{beta / delta - epsilon} ~= N^{1 / 3 - epsilon - 1/1024} >= N^{296/1024}`, we can know that `epsilon <= 0.0432`.

```python
def get_eaten_onion():
    s = ''
    for _ in range(22):
        s += r.recvuntil('\n').decode()
    s = s.replace(' ', '').replace('\n', '').replace('x', '')
    s = s[:173] + '0' + s[173:173+8]
    return bytearray.fromhex(s)

r.recvuntil('seed: ')
r.sendline(onion1.hex())
r.recvuntil('layer: ')
r.sendline('1')
r.recvuntil('Here you go\n')
onion2 = get_eaten_onion()

# f = (x + ((onion2 + (i << 32)) << 296)) ^ 3 - onion1

sage = process(['sage', './solver.sage', str(n), onion1.hex(), onion2.hex()])
onion2 = long_to_bytes(int(sage.recvline().decode().strip()))

r.recvuntil('How would my onion looks like? ')
r.sendline(onion2.hex())
```

```python
import sys

n = int(sys.argv[1])
onion1 = int(sys.argv[2], 16)
onion2 = int(sys.argv[3], 16)

PR.<x> = PolynomialRing(Zmod(n))

for i in range(16):
    f = (x + ((onion2 + (i * 2 ^ 32)) * 2 ^ 296)) ^ 3 - onion1

    res = f.small_roots(beta=1.0, epsilon=0.04)
    if res:
        print(res[0] + ((onion2 + (i * 2 ^ 32)) * 2 ^ 296))
        exit(0)
```

## Level 3

If you see the code of `Fertilizer3`, there's a strange point:

```python
    def swap(self, a, b):
        a, b = b, a

    def bytes_xor(self, a, b):
        return bytes([_a ^ _b for _a, _b in zip(a, b)])

    def rc4_encrypt(self, inputs):
        output = []
        i = self.i
        j = self.j
        s = self.s
        for _ in range(len(inputs)):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            self.swap(s[i], s[j])
            output.append(s[(s[i] + s[j]) % 256])

        self.i = i
        self.j = j
        self.s = s
        return self.bytes_xor(inputs, output)
```

`self.swap()` does not swap, really. Therefore there's a certain period for `self.rc4_encrypt`, which is 192. Just send `9000 ** 3 % 192` to get the flag.

```python
# Level 3
for _ in range(4):
    r.recvuntil('layer: ')
    r.sendline(str(9000 ** 3 % 192))
    r.recvuntil('your onion\n')
    output = get_onion()

r.recvuntil('How would my onion looks like? ')
r.sendline(output.hex())

r.interactive()
```

